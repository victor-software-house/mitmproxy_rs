import Darwin
import Foundation
import Network
import NetworkExtension

enum TransparentProxyError: Error {
    case noRemoteEndpoint
    case noLocalEndpoint
    case unexpectedFlow
}

/// Fails closed: the proxy keeps running when mitmdump detaches, keeps the last intercept spec,
/// and holds in-scope flows until a controller attaches again, refusing a flow only once it
/// waited `holdSeconds`. A process in scope therefore never reaches the network directly while
/// its proxy restarts; a short restart only delays its connections.
class TransparentProxyProvider: NETransparentProxyProvider {
    static let specKey = "lastInterceptActions"
    static let socketKey = "lastUnixSocket"
    /// How long an in-scope flow waits for a controller before it is refused.
    static let holdSeconds = 30.0

    /// Guards `attached`, `unixSocket` and `held` together: a flow is either held before an
    /// attach drains the queue, or sees the attach and is intercepted.
    let state = NSLock()
    /// In-scope flows waiting for a controller.
    var held: [(flow: NEAppProxyFlow, processInfo: ProcessInfo)] = []

    var unixSocket: String?
    var controlChannel: NWConnection?
    var spec: InterceptConf?
    /// True only while a controller's control channel is established.
    var attached = false

    override func startProxy(options: [String: Any]? = nil) async throws {
        log.notice("Starting proxy...")
        // The last spec applies from the start, so flows in scope are refused, not passed,
        // before any controller attaches.
        if let actions = UserDefaults.standard.stringArray(forKey: Self.specKey), !actions.isEmpty {
            self.spec = try? InterceptConf(from: MitmproxyIpc_InterceptConf.with { $0.actions = actions })
            log.notice("Restored intercept spec: \(actions, privacy: .public)")
        }

        let proxySettings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        proxySettings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                // Only TCP reaches the provider: UDP, DNS included, goes to the network as if
                // no proxy ran, and never depends on a controller.
                protocol: .TCP,
                // https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/3143656-includednetworkrules:
                // The matchDirection property must be NETrafficDirection.outbound.
                direction: .outbound
            )
        ]
        try await setTunnelNetworkSettings(proxySettings)
        log.notice("Applied tunnel settings.")

        // The configured socket first, then the last one a controller sent; a dead socket
        // leaves the proxy detached and refusing until a controller attaches.
        let candidates = [
            (self.protocolConfiguration as? NETunnelProviderProtocol)?.serverAddress,
            UserDefaults.standard.string(forKey: Self.socketKey),
        ].compactMap { $0 }
        for path in candidates where !attached {
            await attach(to: path)
        }
        log.notice("Proxy start complete, attached=\(self.attached, privacy: .public)")
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        log.notice("stopProxy \(String(describing: reason), privacy: .public)")
        detach()
    }

    /// A new controller announces its socket path; the running proxy attaches to it, so a
    /// mitmdump restart never stops the proxy.
    /// `status` answers the provider's state without changing it.
    override func handleAppMessage(_ messageData: Data) async -> Data? {
        let text = String(data: messageData, encoding: .utf8)
        if text == "status" {
            return Data(status().utf8)
        }
        guard let path = text, path.hasPrefix("/tmp/") else {
            log.error("Ignoring app message that is neither status nor a socket path.")
            return nil
        }
        log.notice("Controller announced \(path, privacy: .public)")
        await attach(to: path)
        return Data((attached ? "attached" : "detached").utf8)
    }

    func attach(to path: String) async {
        detach()
        let control = NWConnection(to: .unix(path: path), using: .tcp)
        do {
            try await control.establish()
        } catch {
            log.error("Control channel to \(path, privacy: .public) failed: \(error, privacy: .public)")
            control.forceCancel()
            return
        }
        controlChannel = control
        state.lock()
        unixSocket = path
        attached = true
        let waiting = held
        held = []
        state.unlock()
        UserDefaults.standard.set(path, forKey: Self.socketKey)
        log.notice("Attached to \(path, privacy: .public); releasing \(waiting.count, privacy: .public) held flows")
        for (flow, processInfo) in waiting {
            intercept(flow, processInfo, via: path)
        }
        control.stateUpdateHandler = { [weak self] state in
            if case .failed(let err) = state {
                log.notice("Control channel closed (\(err, privacy: .public)); refusing in-scope flows.")
                self?.detach(control)
            }
        }
        Task { [weak self] in
            do {
                while let spec = try await control.receive(ipc: MitmproxyIpc_InterceptConf.self) {
                    log.notice("Received spec: \(String(describing: spec), privacy: .public)")
                    self?.spec = try InterceptConf(from: spec)
                    UserDefaults.standard.set(spec.actions, forKey: Self.specKey)
                }
                log.notice("Control channel ended; refusing in-scope flows.")
                self?.detach(control)
            } catch {
                log.error("Error on control channel: \(String(describing: error), privacy: .public)")
                self?.detach(control)
            }
        }
    }

    /// Drops the controller, or only the given one if it is still the current one.
    /// The proxy and the spec stay.
    func detach(_ which: NWConnection? = nil) {
        if let which = which, which !== controlChannel {
            return
        }
        controlChannel?.forceCancel()
        controlChannel = nil
        state.lock()
        unixSocket = nil
        attached = false
        state.unlock()
    }

    func status() -> String {
        state.lock()
        defer { state.unlock() }
        return "attached=\(attached) held=\(held.count) socket=\(unixSocket ?? "none") spec=\(spec != nil)"
    }

    /// Keeps the flow until a controller attaches; refuses it if none does in `holdSeconds`.
    /// Called with `state` locked.
    func hold(_ flow: NEAppProxyFlow, _ processInfo: ProcessInfo) {
        held.append((flow, processInfo))
        log.notice("Holding in-scope flow until a controller attaches (\(self.held.count, privacy: .public) held)")
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.holdSeconds) { [weak self] in
            guard let self else { return }
            self.state.lock()
            let index = self.held.firstIndex { $0.flow === flow }
            if let index { self.held.remove(at: index) }
            self.state.unlock()
            if index != nil {
                _ = self.refuse(flow, "no controller attached within \(Self.holdSeconds) s")
            }
        }
    }

    /// Takes the flow and closes it with an error: the client sees a failed connection and
    /// retries, where returning false would send it to the network directly.
    func refuse(_ flow: NEAppProxyFlow, _ reason: String) -> Bool {
        log.notice("Refusing in-scope flow: \(reason, privacy: .public)")
        let error = NSError(domain: NEAppProxyErrorDomain, code: NEAppProxyFlowError.notConnected.rawValue)
        Task {
            try? await flow.openOnce()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
        }
        return true
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Called for every new flow that is started.
        // We first want to figure out if we want to intercept this one.
        // Our intercept specs are based on process name and pid, so we first need to convert from
        // audit token to that.

        let processInfo = ProcessInfoCache.getInfo(fromAuditToken: flow.metaData.sourceAppAuditToken)
        guard let processInfo = processInfo else {
            log.debug("Skipping flow without process info.")
            return false
        }

        guard let spec = self.spec else {
            log.debug("Skipping flow, no intercept spec provided.")
            return false
        }
        guard spec.shouldIntercept(processInfo) else {
            return false
        }
        log.debug("Handling new flow: \(String(describing: processInfo), privacy: .public)")

        state.lock()
        let socket = attached ? unixSocket : nil
        if socket == nil {
            hold(flow, processInfo)
        }
        state.unlock()
        if let socket {
            intercept(flow, processInfo, via: socket)
        }
        return true
    }

    /// Hands the flow to the controller listening on `unixSocket`.
    func intercept(_ flow: NEAppProxyFlow, _ processInfo: ProcessInfo, via unixSocket: String) {
        let message: MitmproxyIpc_NewFlow
        do {
            message = try self.makeIpcHandshake(flow: flow, processInfo: processInfo)
        } catch {
            log.error("Failed to create IPC handshake: \(error, privacy: .public), flow=\(flow, privacy: .public)")
            _ = refuse(flow, "no IPC handshake")
            return
        }
        Task {
            do {
                log.debug("Intercepting...")
                try await flow.openOnce()

                let conn = NWConnection(
                    to: .unix(path: unixSocket),
                    using: .tcp
                )
                do {
                    try await conn.establish()
                } catch {
                    flow.closeReadWithError(error)
                    flow.closeWriteWithError(error)
                    throw error
                }

                try await conn.send(ipc: message)
                log.debug("Handshake sent.")

                if let tcp_flow = flow as? NEAppProxyTCPFlow {
                    tcp_flow.outboundCopier(conn)
                    tcp_flow.inboundCopier(conn)
                } else if let udp_flow = flow as? NEAppProxyUDPFlow {
                    udp_flow.outboundCopier(conn)
                    udp_flow.inboundCopier(conn)
                }
            } catch {
                log.error("Error handling flow: \(String(describing: error), privacy: .public)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
            }
        }
    }

    func makeIpcHandshake(flow: NEAppProxyFlow, processInfo: ProcessInfo) throws -> MitmproxyIpc_NewFlow {
        let tunnelInfo = MitmproxyIpc_TunnelInfo.with {
            $0.pid = processInfo.pid
            if let path = processInfo.path {
                $0.processName = path
            }
        }
        
        // Do not use remoteHostname property; for DNS UDP flows that's already pointing at the name that we want to look up.
        // log.debug("remoteHostname: \(String(describing: flow.remoteHostname), privacy: .public) flow:\(String(describing: flow), privacy: .public)")
    
        let message: MitmproxyIpc_NewFlow
        if let tcp_flow = flow as? NEAppProxyTCPFlow {
            guard let remoteEndpoint = tcp_flow.remoteEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noRemoteEndpoint
            }
            // log.debug("remoteEndpoint: \(String(describing: remoteEndpoint), privacy: .public)")
            // It would be nice if we could also include info on the local endpoint here, but that's not exposed.
            message = MitmproxyIpc_NewFlow.with {
                $0.tcp = MitmproxyIpc_TcpFlow.with {
                    $0.remoteAddress = MitmproxyIpc_Address.init(endpoint: remoteEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else if let udp_flow = flow as? NEAppProxyUDPFlow {
            guard let localEndpoint = udp_flow.localEndpoint as? NWHostEndpoint else {
                throw TransparentProxyError.noLocalEndpoint
            }
            message = MitmproxyIpc_NewFlow.with {
                $0.udp = MitmproxyIpc_UdpFlow.with {
                    $0.localAddress = MitmproxyIpc_Address.init(endpoint: localEndpoint)
                    $0.tunnelInfo = tunnelInfo
                }
            }
        } else {
            throw TransparentProxyError.unexpectedFlow
        }
        return message
    }
}
