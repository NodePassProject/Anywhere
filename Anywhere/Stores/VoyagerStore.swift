//
//  VoyagerStore.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation
import Observation
import StoreKit

@MainActor
@Observable
final class VoyagerStore {
    static let shared = VoyagerStore()
    
    static let productID = "nonconsumable.voyager"

    private(set) var product: Product?
    private(set) var isMember = false
    private(set) var isLoadingProduct = false
    private(set) var purchaseInFlight = false
    
    var displayPrice: String? { product?.displayPrice }
    var productName: String? { product?.displayName }

    var isPresentingVoyagerView = false

    @ObservationIgnored private var updatesTask: Task<Void, Never>?

    private init() {
        isMember = AWCore.getVoyagerMembership()
        updatesTask = listenForTransactions()
        Task {
            await loadProduct()
            await refreshEntitlement()
        }
    }

    deinit {
        updatesTask?.cancel()
    }

    // MARK: - Loading

    func loadProduct() async {
        guard product == nil else { return }
        isLoadingProduct = true
        defer { isLoadingProduct = false }
        product = try? await Product.products(for: [Self.productID]).first
    }

    // MARK: - Entitlement
    
    func refreshEntitlement() async {
        guard let result = await Transaction.latest(for: Self.productID),
              case .verified(let transaction) = result,
              transaction.productID == Self.productID else {
            return
        }
        setMember(transaction.revocationDate == nil)
    }
    
    private func setMember(_ value: Bool) {
        isMember = value
        AWCore.setVoyagerMembership(value)
    }
    
    func verificationToken() async -> String? {
        for await result in Transaction.currentEntitlements {
            if case .verified(let transaction) = result,
               transaction.productID == Self.productID,
               transaction.revocationDate == nil {
                return result.jwsRepresentation
            }
        }
        return nil
    }

    // MARK: - Purchase
    
    @discardableResult
    func purchase() async throws -> Bool {
        if product == nil { await loadProduct() }
        guard let product else { throw StoreError.productUnavailable }

        purchaseInFlight = true
        defer { purchaseInFlight = false }

        let result = try await product.purchase()
        switch result {
        case .success(let verification):
            let transaction = try checkVerified(verification)
            await transaction.finish()
            setMember(true)
            return true
        case .userCancelled, .pending:
            return false
        @unknown default:
            return false
        }
    }

    // MARK: - Restore
    
    func restore() async throws {
        try await AppStore.sync()
        await refreshEntitlement()
    }

    // MARK: - Transaction updates

    private func listenForTransactions() -> Task<Void, Never> {
        Task { [weak self] in
            for await result in Transaction.updates {
                guard case .verified(let transaction) = result else { continue }
                await transaction.finish()
                await self?.refreshEntitlement()
            }
        }
    }

    private func checkVerified<T>(_ result: VerificationResult<T>) throws -> T {
        switch result {
        case .unverified(_, let error):
            throw error
        case .verified(let safe):
            return safe
        }
    }

    enum StoreError: LocalizedError {
        case productUnavailable

        var errorDescription: String? {
            switch self {
            case .productUnavailable:
                return String(localized: "Anywhere Voyager is currently unavailable. Please try again later.")
            }
        }
    }
}
