//
//  ConnectionCore+InitialCrumbling.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

extension ConnectionCore {
    func crumbleInitialCrypto(
        space: PacketNumberSpace,
        left: Int,
        into frames: inout [CrumbledFrame]
    ) -> (popped: Range<UInt64>, deferred: Range<UInt64>?)? {
        guard left > 0, let run = space.cryptoSend.firstPendingRun() else {
            return nil
        }
        let cryptoOffset = run.range.lowerBound
        var maxAdditions = InitialCrumbling.maxAddedFrames
        let frameOverhead = OutputBuffer.cryptoFrameOverhead(offset: cryptoOffset + UInt64(left) - 1, length: left)
        var budget = frameOverhead * maxAdditions
        guard left > budget,
              let maxLength = OutputBuffer.cryptoDataCapacity(
                  offset: cryptoOffset,
                  available: left - budget,
                  wanted: left - budget
              ) else {
            return nil
        }
        let end = Swift.min(run.range.upperBound, cryptoOffset + UInt64(maxLength))
        let isFollowed = end < run.range.upperBound || run.isFollowed
        frames.removeAll(keepingCapacity: true)
        var start = cryptoOffset
        for boundary in space.cryptoChunkStarts where boundary > start && boundary < end {
            frames.append(.crypto(offset: start, length: Int(boundary - start)))
            start = boundary
        }
        frames.append(.crypto(offset: start, length: Int(end - start)))
        var deferred: Range<UInt64>?
        if frames.count < InitialCrumbling.maxFrameCount,
           case .crypto(let offset, let length) = frames[0],
           let name = space.cryptoSend.withBytes(offset: offset, length: length, InitialCrumbling.findServerName),
           name.count > 1 {
            if isFollowed {
                let part = offset + UInt64(name.lowerBound)..<offset + UInt64(name.upperBound)
                let removed = InitialCrumbling.removePartially(part, from: &frames, using: &self.pcg)
                budget += Int(removed.upperBound - removed.lowerBound)
                deferred = removed
            } else {
                InitialCrumbling.split(&frames, at: name.lowerBound + name.count / 2)
            }
        }
        if frames.count < maxAdditions + 1 {
            maxAdditions -= frames.count - 1
            InitialCrumbling.splitRandomly(&frames, maxAdditions: maxAdditions, using: &self.pcg)
        }
        for case .crypto(let offset, let length) in frames.dropFirst() {
            budget -= OutputBuffer.cryptoFrameOverhead(offset: offset, length: length)
        }
        InitialCrumbling.appendPingAndPadding(to: &frames, budget: budget, using: &self.pcg)
        InitialCrumbling.permute(&frames, using: &self.pcg)
        return (cryptoOffset..<end, deferred)
    }
}
