//
//  MITMExportOperation.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation

@MainActor
struct MITMExportScheduler {
    let debouncer: Debouncer
    let ruleSetStore: MITMRuleSetStore
    let moduleStore: ModuleStore

    func schedule() {
        debouncer.schedule { [ruleSetStore, moduleStore] in
            let ruleSets = moduleStore.exportedMITMRuleSets + ruleSetStore.ruleSets
            await MITMExportOperation(ruleSets: ruleSets).run()
        }
    }
}

@MainActor
struct MITMExportOperation {
    let ruleSets: [MITMRuleSet]

    func run() async {
        let ruleSets = ruleSets
        await Task.detached {
            if MITMSnapshot(ruleSets: ruleSets).exportBinaryToAppGroup() {
                AWNotificationCenter.notifyMITMChanged()
            }
        }.value
    }
}
