//
//  WidgetBundle.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/6/26.
//

import WidgetKit
import SwiftUI

@main
struct AnywhereWidgetBundle: WidgetBundle {
    var body: some Widget {
        if #available(iOS 18.0, *) {
            VPNToggleControl()
        }
    }
}
