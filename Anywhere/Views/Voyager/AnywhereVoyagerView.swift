//
//  AnywhereVoyagerView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import SwiftUI

struct AnywhereVoyagerView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(VoyagerStore.self) private var store

    @State private var showOnboarding = false
    @State private var revealed = false
    @State private var glow = false

    var body: some View {
        ZStack {
            VoyagerBackground()
            
            GeometryReader { geo in
                let width = geo.size.width
                let height = geo.size.height
                
                ZStack {
                    Image("anywhere")
                        .resizable()
                        .scaledToFit()
                        .frame(width: min(width * 0.7, 400), height: min(height * 0.4, 400))
                        .foregroundStyle(cloudGradient)
                        .shadow(color: Color(hex: 0xF4C98E, alpha: glow ? 0.70 : 0.50), radius: glow ? 32 : 24)
                        .shadow(color: Color(hex: 0xFCEDC6, alpha: glow ? 0.42 : 0.28), radius: glow ? 14 : 10)
                        .animation(.easeInOut(duration: 2.8).repeatForever(autoreverses: true), value: glow)
                        .scaleEffect(revealed || reduceMotion ? 1 : 0.94)
                        .opacity(revealed ? 1 : 0)
                        .offset(y: revealed || reduceMotion ? 0 : 16)
                        .animation(.easeOut(duration: 0.7), value: revealed)
                        .position(x: width * 0.5, y: height * 0.3)
                    
                    Text("Voyager")
                        .font(.system(size: 52, weight: .semibold, design: .serif))
                        .tracking(2)
                        .foregroundStyle(goldGradient)
                        .shadow(color: Color(hex: 0xF0B85E, alpha: 0.45), radius: 9)
                        .opacity(revealed ? 1 : 0)
                        .offset(y: revealed || reduceMotion ? 0 : 16)
                        .animation(.easeOut(duration: 0.7).delay(0.12), value: revealed)
                        .position(x: width * 0.5, y: height * 0.585)
                }
            }
            
            VStack {
                HStack {
                    closeButton
                        .opacity(revealed ? 1 : 0)
                        .animation(.easeOut(duration: 0.6).delay(0.30), value: revealed)
                        .padding(.leading, 32)
                        .padding(.top, 20)
                    Spacer()
                }
                Spacer()
            }
            
            VStack {
                Spacer()
                bottomAction
                    .opacity(revealed ? 1 : 0)
                    .offset(y: revealed || reduceMotion ? 0 : 20)
                    .animation(.easeOut(duration: 0.7).delay(0.25), value: revealed)
                    .animation(.easeInOut(duration: 0.4), value: store.isMember)
                    .padding(.horizontal, 24)
                    .padding(.bottom, 20)
            }
        }
        .onAppear {
            revealed = true
            if !reduceMotion { glow = true }
        }
        .sheet(isPresented: $showOnboarding) {
            VoyagerOnboardingView()
                .environment(store)
        }
    }

    @ViewBuilder
    private var cloudGradient: LinearGradient {
        LinearGradient(
            colors: [Color(hex: 0xC4C7E6), Color(hex: 0xDCD3E2), Color(hex: 0xFCEDC6)],
            startPoint: .top,
            endPoint: .bottom
        )
    }

    @ViewBuilder
    private var goldGradient: LinearGradient {
        LinearGradient(
            colors: [Color(hex: 0xFBEFD2), Color(hex: 0xE7C98D)],
            startPoint: .top,
            endPoint: .bottom
        )
    }

    @ViewBuilder
    private var bottomAction: some View {
        if store.isMember {
            memberBadge
                .transition(.opacity)
        } else {
            subscribeButton
                .transition(.opacity)
        }
    }

    @ViewBuilder
    private var subscribeButton: some View {
        Button {
            showOnboarding = true
        } label: {
            Text("Start Journey")
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(Color(hex: 0x161326))
                .frame(maxWidth: .infinity, minHeight: 54)
                .background(goldGradient, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .shadow(color: Color(hex: 0xF0B85E).opacity(0.35), radius: 14, y: 4)
        }
    }

    @ViewBuilder
    private var memberBadge: some View {
        Text("Member \(Image(systemName: "checkmark.seal.fill"))")
            .textCase(.uppercase)
            .font(.body.weight(.semibold))
            .foregroundStyle(goldGradient)
            .frame(maxWidth: .infinity, minHeight: 54)
    }
    
    @ViewBuilder
    private var closeButton: some View {
        Button {
            dismiss()
        } label: {
            Image(systemName: "xmark")
                .font(.system(size: 20))
                .foregroundStyle(.white.opacity(0.85))
        }
        .accessibilityLabel("Close")
    }
}

struct VoyagerBackground: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    
    @State private var twinkle = false

    private let designWidth: CGFloat = 440
    private let designHeight: CGFloat = 956
 
    var body: some View {
        GeometryReader { geo in
            let width = geo.size.width
            let height = geo.size.height
            let scale = width / designWidth
            let P: (CGFloat, CGFloat) -> CGPoint = { CGPoint(x: $0 / designWidth * width, y: $1 / designHeight * height) }
 
            ZStack {
                Rectangle().fill(skyGradient)

                Rectangle()
                    .fill(EllipticalGradient(
                        gradient: Gradient(stops: dawnStops),
                        center: .center,
                        startRadiusFraction: 0,
                        endRadiusFraction: 0.5))
                    .frame(width: width * (720 / designWidth), height: height * (500 / designHeight))
                    .position(P(220, 418))

                Path { p in
                    p.move(to: P(-20, 470))
                    p.addQuadCurve(to: P(460, 470), control: P(220, 438))
                }
                .stroke(Color(hex: 0xF4D9A8, alpha: 0.18), lineWidth: 1.2 * scale)

                ForEach(stars.indices, id: \.self) { i in
                    Circle()
                        .fill(Color(hex: 0xFBF4DE, alpha: stars[i].o))
                        .frame(width: stars[i].r * 2 * scale, height: stars[i].r * 2 * scale)
                        .opacity(twinkle ? 0.45 + 0.10 * Double(i % 3) : 1.0)
                        .animation(.easeInOut(duration: 2.0 + 0.7 * Double(i % 4))
                            .repeatForever(autoreverses: true)
                            .delay(0.35 * Double(i)), value: twinkle)
                        .position(P(stars[i].x, stars[i].y))
                }
                Sparkle()
                    .fill(Color(hex: 0xFFF6DF, alpha: 0.85))
                    .frame(width: 16 * scale, height: 16 * scale)
                    .scaleEffect(twinkle ? 1.12 : 1.0)
                    .animation(.easeInOut(duration: 2.8).repeatForever(autoreverses: true), value: twinkle)
                    .position(P(210, 60))

                Path { p in
                    p.move(to: P(58, 168))
                    p.addCurve(to: P(384, 132), control1: P(150, 92), control2: P(292, 92))
                }
                .stroke(Color(hex: 0xF6E2B8, alpha: 0.5),
                        style: StrokeStyle(lineWidth: 1.6 * scale, lineCap: .round, dash: [1.5 * scale, 8 * scale]))
 
                Circle()                                   // origin dot
                    .fill(Color(hex: 0xE9D9B8, alpha: 0.75))
                    .frame(width: 3.6 * scale, height: 3.6 * scale)
                    .position(P(58, 168))
 
                Circle()                                   // waypoint glow
                    .fill(Color(hex: 0xFBC97A, alpha: 0.5))
                    .frame(width: 12 * scale, height: 12 * scale)
                    .blur(radius: 3.5 * scale)
                    .scaleEffect(twinkle ? 1.22 : 1.0)
                    .animation(.easeInOut(duration: 2.3).repeatForever(autoreverses: true).delay(0.4), value: twinkle)
                    .position(P(384, 132))
 
                Sparkle()                                  // waypoint star
                    .fill(Color(hex: 0xFFF3D6))
                    .frame(width: 16 * scale, height: 16 * scale)
                    .scaleEffect(twinkle ? 1.18 : 1.0)
                    .animation(.easeInOut(duration: 2.3).repeatForever(autoreverses: true).delay(0.4), value: twinkle)
                    .position(P(384, 132))

                Rectangle().fill(vignette(height: height))
            }
            .clipped()
        }
        .ignoresSafeArea()
        .onAppear { if !reduceMotion { twinkle = true } }
    }
 
    // MARK: Star
 
    private struct Star { let x, y, r, o: CGFloat }
    private let stars: [Star] = [
        Star(x: 95,  y: 70,  r: 1.2, o: 0.80),
        Star(x: 150, y: 138, r: 0.8, o: 0.60),
        Star(x: 270, y: 150, r: 0.9, o: 0.55),
        Star(x: 330, y: 82,  r: 1.1, o: 0.72),
        Star(x: 300, y: 40,  r: 1.0, o: 0.70),
        Star(x: 38,  y: 230, r: 0.9, o: 0.50),
        Star(x: 405, y: 158, r: 0.8, o: 0.50),
        Star(x: 415, y: 250, r: 0.7, o: 0.45),
        Star(x: 30,  y: 300, r: 0.8, o: 0.50),
    ]
    
    // MARK: Sparkle
    
    private struct Sparkle: Shape {
        var innerRatio: CGFloat = 0.25
        func path(in rect: CGRect) -> Path {
            let c = CGPoint(x: rect.midX, y: rect.midY)
            let R = min(rect.width, rect.height) / 2
            let r = R * innerRatio
            let d = r / CGFloat(2).squareRoot()
            var p = Path()
            p.move(to: CGPoint(x: c.x, y: c.y - R))
            p.addLine(to: CGPoint(x: c.x + d, y: c.y - d))
            p.addLine(to: CGPoint(x: c.x + R, y: c.y))
            p.addLine(to: CGPoint(x: c.x + d, y: c.y + d))
            p.addLine(to: CGPoint(x: c.x, y: c.y + R))
            p.addLine(to: CGPoint(x: c.x - d, y: c.y + d))
            p.addLine(to: CGPoint(x: c.x - R, y: c.y))
            p.addLine(to: CGPoint(x: c.x - d, y: c.y - d))
            p.closeSubpath()
            return p
        }
    }
 
    // MARK: Gradients
 
    private var skyGradient: LinearGradient {
        LinearGradient(gradient: Gradient(stops: [
            .init(color: Color(hex: 0x05081A), location: 0.00),
            .init(color: Color(hex: 0x0F1538), location: 0.20),
            .init(color: Color(hex: 0x232653), location: 0.40),
            .init(color: Color(hex: 0x3A3164), location: 0.55),
            .init(color: Color(hex: 0x4A3A6B), location: 0.64),
            .init(color: Color(hex: 0x2A2150), location: 0.72),
            .init(color: Color(hex: 0x0A0E27), location: 1.00),
        ]), startPoint: .top, endPoint: .bottom)
    }
 
    private var dawnStops: [Gradient.Stop] {
        [
            .init(color: Color(hex: 0xFFC98C, alpha: 0.85), location: 0.00),
            .init(color: Color(hex: 0xF4A85E, alpha: 0.62), location: 0.16),
            .init(color: Color(hex: 0xC9673E, alpha: 0.30), location: 0.40),
            .init(color: Color(hex: 0x9C4F35, alpha: 0.12), location: 0.70),
            .init(color: Color(hex: 0x9C4F35, alpha: 0.00), location: 1.00),
        ]
    }
 
    private func vignette(height: CGFloat) -> RadialGradient {
        RadialGradient(
            gradient: Gradient(colors: [Color(hex: 0x05060F, alpha: 0),
                                        Color(hex: 0x05060F, alpha: 0.55)]),
            center: UnitPoint(x: 0.5, y: 0.45),
            startRadius: height * 0.40,
            endRadius: height * 0.64)
    }
}

#Preview {
    AnywhereVoyagerView()
        .environment(VoyagerStore.shared)
}
