//
//  MITMByteLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
import Synchronization

protocol MITMByteLeg: AnyObject {
    var negotiatedALPN: String { get }
    
    func prependToReceiveBuffer(_ data: Data)
    
    func receive(completion: @escaping (Data?, Error?) -> Void)

    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)

    func cancel()
}

extension TLSRecordConnection: MITMByteLeg {}

nonisolated final class PlaintextLeg: MITMByteLeg {
    let negotiatedALPN: String = ""

    private let transport: any RawTransport

    private struct State {
        var prepended = Data()
        var cancelled = false
    }
    private let state = Mutex(State())

    init(transport: any RawTransport) {
        self.transport = transport
    }

    func prependToReceiveBuffer(_ data: Data) {
        guard !data.isEmpty else { return }
        state.withLock { $0.prepended.append(data) }
    }

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        // Extract under the lock; `completion` is invoked outside it.
        let (buffered, isCancelled): (Data?, Bool) = state.withLock { state in
            if !state.prepended.isEmpty {
                let data = state.prepended
                state.prepended = Data()
                return (data, false)
            }
            return (nil, state.cancelled)
        }
        if let buffered {
            completion(buffered, nil)
            return
        }
        if isCancelled {
            completion(nil, nil)
            return
        }

        transport.receive { data, isComplete, error in
            if let error {
                completion(nil, error)
            } else if let data, !data.isEmpty {
                completion(data, nil)
            } else if isComplete {
                completion(nil, nil)
            } else {
                completion(nil, nil)
            }
        }
    }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        transport.send(data: data, completion: completion)
    }

    func send(data: Data) {
        transport.send(data: data)
    }

    func cancel() {
        state.withLock { state in
            state.cancelled = true
            state.prepended = Data()
        }
        transport.forceCancel()
    }
}
