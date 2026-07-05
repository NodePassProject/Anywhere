//
//  DetailRevealScrollView.swift
//  Anywhere
//
//  Created by NodePassProject on 7/5/26.
//

import SwiftUI

struct DetailRevealScrollView<Fold: View, Detail: View>: View {
    private let revealsDetail: Bool
    private let fold: Fold
    private let detail: Detail

    @State private var metrics = DetailRevealMetrics()
    @State private var scrollPosition = ScrollPosition()
    @State private var snapFeedbackCount = 0

    init(
        revealsDetail: Bool,
        @ViewBuilder fold: () -> Fold,
        @ViewBuilder detail: () -> Detail
    ) {
        self.revealsDetail = revealsDetail
        self.fold = fold()
        self.detail = detail()
    }

    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(spacing: 0) {
                    fold
                        .frame(maxWidth: .infinity, minHeight: geometry.size.height)
                        .overlay(alignment: .bottom) {
                            if revealsDetail {
                                PullUpIndicator()
                                    .transition(.blurReplace)
                            }
                        }
                        .padding(.bottom, geometry.safeAreaInsets.bottom)
                        .onGeometryChange(for: CGRect.self) { proxy in
                            proxy.frame(in: .scrollView)
                        } action: { frame in
                            metrics.foldHeight = frame.height
                            metrics.offset = -frame.minY
                            if frame.minY >= -DetailRevealSnapBehavior.boundaryTolerance {
                                metrics.settledPage = .fold
                            }
                        }
                        .id(DetailRevealPage.fold)

                    if revealsDetail {
                        detail
                            .transition(.blurReplace)
                            .id(DetailRevealPage.detail)
                    }
                }
            }
            .scrollIndicators(.never)
            .scrollTargetBehavior(DetailRevealSnapBehavior(
                metrics: metrics,
                isEnabled: revealsDetail
            ))
            .scrollBounceBehavior(.basedOnSize, axes: .vertical)
            .scrollPosition($scrollPosition)
            .onScrollPhaseChange { _, newPhase in
                handlePhaseChange(newPhase)
            }
            .sensoryFeedback(.impact(weight: .light), trigger: snapFeedbackCount)
        }
    }

    private func handlePhaseChange(_ phase: ScrollPhase) {
        switch phase {
        case .tracking, .interacting:
            metrics.pendingSnap = nil
        case .decelerating, .idle:
            guard let page = metrics.pendingSnap else { return }
            metrics.pendingSnap = nil
            let isPageChange = page != metrics.settledPage
            metrics.settledPage = page
            snap(to: page, playFeedback: isPageChange)
        default:
            break
        }
    }

    private func snap(to page: DetailRevealPage, playFeedback: Bool) {
        Task { @MainActor in
            if playFeedback { snapFeedbackCount += 1 }
            withAnimation(.snappy(duration: 0.3, extraBounce: 0)) {
                scrollPosition.scrollTo(id: page, anchor: .top)
            }
        }
    }
}

// MARK: - Snapping

private nonisolated enum DetailRevealPage: Hashable {
    case fold
    case detail
}

private final class DetailRevealMetrics {
    /// Height of the fold page — the offset at which detail is fully revealed.
    var foldHeight: CGFloat = 0
    /// Current scroll offset (0 = fold page flush with the top).
    var offset: CGFloat = 0
    /// The page the scroll view last settled on.
    var settledPage: DetailRevealPage = .fold
    /// Page picked for the gesture in flight; consumed when the finger lifts.
    var pendingSnap: DetailRevealPage?
}

private struct DetailRevealSnapBehavior: ScrollTargetBehavior {
    /// Slack for float comparisons against page boundaries.
    static let boundaryTolerance: CGFloat = 0.5

    let metrics: DetailRevealMetrics
    let isEnabled: Bool

    func updateTarget(_ target: inout ScrollTarget, context: TargetContext) {
        guard isEnabled else { return }

        // Offset at which the detail page is flush with the top, capped by how
        // far the content can actually scroll.
        let commitOffset = min(
            metrics.foldHeight,
            context.contentSize.height - context.containerSize.height
        )
        guard commitOffset > 0 else {
            metrics.pendingSnap = nil
            return
        }

        let projected = target.rect.origin.y

        // Scrolled within the detail content: keep flings from sailing back
        // past the fold. Returning to the fold page takes a second gesture
        // once settled at its top.
        if metrics.offset > commitOffset + Self.boundaryTolerance {
            metrics.pendingSnap = nil
            if projected < commitOffset {
                target.rect.origin.y = commitOffset
            }
            return
        }

        // Otherwise only intervene around the fold: the gesture either ends
        // between the two pages or would cross a page in one go.
        let landsBetweenPages = projected > 0 && projected < commitOffset
        let crossesIntoDetail = metrics.offset < commitOffset - Self.boundaryTolerance && projected >= commitOffset
        let crossesToTop = metrics.offset > Self.boundaryTolerance && projected <= 0
        guard landsBetweenPages || crossesIntoDetail || crossesToTop else {
            metrics.pendingSnap = nil
            return
        }

        let page: DetailRevealPage = projected >= commitOffset / 2 ? .detail : .fold
        target.rect.origin.y = page == .detail ? commitOffset : 0
        metrics.pendingSnap = page
    }
}

// MARK: - Pull-Up Indicator

private struct PullUpIndicator: View {
    var body: some View {
        Image(systemName: "chevron.compact.up")
            .font(.title)
            .foregroundStyle(.secondary)
            .phaseAnimator([0.0, -6.0]) { view, offset in
                view.offset(y: offset)
            } animation: { _ in
                .easeInOut(duration: 1.1)
            }
            .padding(.bottom, 8)
    }
}
