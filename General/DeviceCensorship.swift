//
//  DeviceCensorship.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

public enum DeviceCensorship {
    public static func isChinaDevice() -> Bool {
        let bannedCharacter = "\u{1F1F9}\u{1F1FC}" as NSString
        var imageData: Data
#if canImport(UIKit)
        let attributes = [NSAttributedString.Key.font:
                            UIFont.systemFont(ofSize: 8)]
        UIGraphicsBeginImageContext(bannedCharacter.size(withAttributes: attributes))
        bannedCharacter.draw(at: CGPoint(x: 0, y: 0), withAttributes: attributes)
        var imagePNG: Data?
        if let charImage = UIGraphicsGetImageFromCurrentImageContext() {
            imagePNG = charImage.pngData()
        }
        UIGraphicsEndImageContext()
        guard let imagePNG else {
            return false
        }
        guard let uiImage = UIImage(data: imagePNG) else {
            return false
        }
        guard let cgImage = uiImage.cgImage else { return false }
        guard let cgImageData = cgImage.dataProvider?.data as Data? else { return false }
        imageData = cgImageData
#elseif canImport(AppKit)
        let attributes = [NSAttributedString.Key.font:
                            NSFont.systemFont(ofSize: 8)]
        let characterSize = bannedCharacter.size(withAttributes: attributes)
        let characterRect = NSRect(origin: .zero, size: characterSize)
        
        let characterBitmap = NSBitmapImageRep(bitmapDataPlanes: nil,
                                               pixelsWide: Int(characterSize.width),
                                               pixelsHigh: Int(characterSize.height),
                                               bitsPerSample: 8,
                                               samplesPerPixel: 4,
                                               hasAlpha: true,
                                               isPlanar: false,
                                               colorSpaceName: NSColorSpaceName.calibratedRGB,
                                               bytesPerRow: 0,
                                               bitsPerPixel: 0)
        
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: characterBitmap!)
        NSGraphicsContext.current?.imageInterpolation = .high
        
        bannedCharacter.draw(in: characterRect, withAttributes: attributes)
        
        NSGraphicsContext.restoreGraphicsState()
        
        guard let imagePNG = characterBitmap?.representation(using: .png, properties: [:]) else {
            return false
        }
        
        guard let nsImage = NSImage(data: imagePNG) else {
            return false
        }
        guard let cgImage = nsImage.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
            return false
        }
        guard let cgImageData = cgImage.dataProvider?.data as Data? else { return false }
        imageData = cgImageData
#endif
        let rawData: UnsafePointer<UInt8> = CFDataGetBytePtr(imageData as CFData)
        for index in stride(from: 0, to: imageData.count, by: 4) {
            let r = rawData[index]
            let g = rawData[index + 1]
            let b = rawData[index + 2]
            if !(r == g && g == b) {
                return false
            }
        }
        return true
    }
}
