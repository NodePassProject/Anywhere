//
//  MITMByteLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation

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
    private let lock = UnfairLock()
    private var prepended = Data()
    private var cancelled = false

    init(transport: any RawTransport) {
        self.transport = transport
    }

    func prependToReceiveBuffer(_ data: Data) {
        guard !data.isEmpty else { return }
        lock.lock()
        prepended.append(data)
        lock.unlock()
    }

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !prepended.isEmpty {
            let data = prepended
            prepended = Data()
            lock.unlock()
            completion(data, nil)
            return
        }
        if cancelled {
            lock.unlock()
            completion(nil, nil)
            return
        }
        lock.unlock()

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
        lock.lock()
        cancelled = true
        prepended = Data()
        lock.unlock()
        transport.forceCancel()
    }
}
