//
//  PageView.swift
//  Anywhere
//
//  Created by NodePassProject on 9/21/26.
//

import SwiftUI

struct PageView<Content: View>: View {
    @Binding var selection: Int
    @ViewBuilder let content: Content

    @State private var progress: CGFloat = 0

    var body: some View {
        GeometryReader { proxy in
            let safeAreaInsets = proxy.safeAreaInsets
            Group(subviews: content) { subviews in
                ScrollView(.horizontal) {
                    HStack(spacing: 0) {
                        ForEach(subviews.indices, id: \.self) { index in
                            subviews[index]
                                .padding(.leading, safeAreaInsets.leading)
                                .padding(.trailing, safeAreaInsets.trailing)
                                .containerRelativeFrame(.horizontal)
                                .id(index)
                        }
                    }
                    .scrollTargetLayout()
                }
                .scrollTargetBehavior(.paging)
                .scrollIndicators(.hidden)
                .scrollPosition(id: scrolledPage)
                .onScrollGeometryChange(for: CGFloat.self) { geometry in
                    guard geometry.bounds.width > 0 else { return 0 }
                    let lastPage = CGFloat(max(subviews.count - 1, 0))
                    return min(max(geometry.bounds.minX / geometry.bounds.width, 0), lastPage)
                } action: { _, newValue in
                    progress = newValue
                }
                .ignoresSafeArea(.container, edges: .horizontal)
                .safeAreaInset(edge: .bottom) {
                    PageIndicator(
                        labels: subviews.map(\.containerValues.pageIndicatorLabel),
                        progress: progress,
                        selection: $selection
                    )
                }
            }
        }
    }

    private var scrolledPage: Binding<Int?> {
        Binding {
            selection
        } set: { page in
            if let page {
                selection = page
            }
        }
    }
}

extension ContainerValues {
    @Entry var pageIndicatorLabel: LocalizedStringKey? = nil
}

extension View {
    func pageIndicator(label: LocalizedStringKey) -> some View {
        containerValue(\.pageIndicatorLabel, label)
    }
}

private struct PageIndicator: View {
    private static let dotSize: CGFloat = 6
    private static let dotSpacing: CGFloat = 8
    private static let pillHeight: CGFloat = 24
    private static let pillHorizontalInset: CGFloat = 12
    private static let selectedOpacity: CGFloat = 1
    private static let unselectedOpacity: CGFloat = 0.3

    let labels: [LocalizedStringKey?]
    let progress: CGFloat
    @Binding var selection: Int

    var body: some View {
        if #available(iOS 26.0, *) {
            dots
                .glassEffect(.regular.interactive(), in: .capsule)
        } else {
            dots
        }
    }

    private var dots: some View {
        HStack(spacing: 0) {
            ForEach(labels.indices, id: \.self) { index in
                Button {
                    withAnimation(.snappy) {
                        selection = index
                    }
                } label: {
                    Circle()
                        .fill(.primary.opacity(opacity(for: index)))
                        .frame(width: Self.dotSize, height: Self.dotSize)
                        .frame(width: Self.dotSize + Self.dotSpacing, height: Self.pillHeight)
                        .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(labels[index] ?? "")
                .accessibilityAddTraits(selection == index ? .isSelected : [])
            }
        }
        .padding(.horizontal, Self.pillHorizontalInset - Self.dotSpacing / 2)
        .padding(.bottom)
    }

    private func opacity(for index: Int) -> CGFloat {
        let distance = min(1, abs(progress - CGFloat(index)))
        return Self.selectedOpacity - (Self.selectedOpacity - Self.unselectedOpacity) * distance
    }
}
