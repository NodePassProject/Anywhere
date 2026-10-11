//
//  PacketNumberSpace.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct BufferedPacket {
    var bytes: [UInt8]
    var path: QUICPath
    var datagramLength: Int
    var receivedAt: Nanoseconds
}

final class PacketNumberSpace {
    static let maxBufferedPackets = 4
    static let maxReorderedCryptoData: UInt64 = 65536
    static let cryptoChunkCapacity = 1024

    let level: QUICEncryptionLevel
    var readKeys: PacketKeys?
    var writeKeys: PacketKeys?
    var nextPacketNumber: UInt64 = 0
    var sent = SentPacketTracker()
    var ackTracker = ACKTracker()
    var cryptoSend = SendBuffer()
    private(set) var cryptoChunkStarts: [UInt64] = []
    private var cryptoChunkEnd: UInt64 = 0
    var cryptoReceive = ReceiveBuffer()
    var cryptoReceivedEnd: UInt64 = 0
    var pendingControlFrames: [ControlFrame] = []
    var bufferedPackets: [BufferedPacket] = []
    var nonACKElicitingStart: Nanoseconds = Time.never
    var lastSentAt: Nanoseconds = Time.never

    init(level: QUICEncryptionLevel) {
        self.level = level
    }

    var isApplication: Bool { self.level == .application }

    var maxCryptoOffset: UInt64 {
        switch self.level {
        case .initial:
            return 65536
        case .handshake:
            return 65536
        case .application:
            return 4 * 1024 * 1024
        }
    }

    func selectPacketNumberLength() -> Int {
        return PacketNumber.encodedLength(self.nextPacketNumber, largestAcknowledged: self.sent.largestAcknowledged)
    }

    var hasPendingCryptoData: Bool {
        return self.cryptoSend.hasPendingData
    }

    func appendCryptoData(_ bytes: UnsafeRawBufferPointer) {
        guard !bytes.isEmpty else {
            return
        }
        let offset = self.cryptoSend.endOffset
        if self.level == .initial,
           self.cryptoChunkStarts.isEmpty || self.cryptoChunkEnd - offset < UInt64(bytes.count) {
            self.cryptoChunkStarts.append(offset)
            self.cryptoChunkEnd = offset + UInt64(Swift.max(Self.cryptoChunkCapacity, bytes.count))
        }
        self.cryptoSend.append(bytes)
    }

    func buffer(_ packet: UnsafeRawBufferPointer, path: QUICPath, datagramLength: Int, receivedAt: Nanoseconds) {
        guard self.bufferedPackets.count < Self.maxBufferedPackets else {
            return
        }
        self.bufferedPackets.append(
            BufferedPacket(
                bytes: Array(packet),
                path: path,
                datagramLength: datagramLength,
                receivedAt: receivedAt
            )
        )
    }
}
