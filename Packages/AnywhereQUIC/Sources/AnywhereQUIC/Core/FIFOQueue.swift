//
//  FIFOQueue.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/6/26.
//

struct FIFOQueue<Element> {
    private var storage: [Element?] = []
    private var head = 0

    var count: Int { self.storage.count - self.head }

    var isEmpty: Bool { self.head == self.storage.count }

    var first: Element? { self.isEmpty ? nil : self.storage[self.head] }

    func contains(where predicate: (Element) throws -> Bool) rethrows -> Bool {
        for index in self.head..<self.storage.count where try predicate(self.storage[index]!) {
            return true
        }
        return false
    }

    mutating func append(_ element: Element) {
        self.storage.append(element)
    }

    mutating func append(contentsOf elements: some Collection<Element>) {
        self.storage.reserveCapacity(self.storage.count + elements.count)
        for element in elements {
            self.storage.append(element)
        }
    }

    @discardableResult
    mutating func removeFirst() -> Element {
        precondition(!self.isEmpty, "removeFirst on an empty FIFOQueue")
        let element = self.storage[self.head].take()!
        self.head += 1
        if self.head == self.storage.count {
            self.storage.removeAll(keepingCapacity: true)
            self.head = 0
        } else if self.head >= 32, self.head * 2 >= self.storage.count {
            self.storage.removeFirst(self.head)
            self.head = 0
        }
        return element
    }

    mutating func removeAll() {
        self.storage.removeAll()
        self.head = 0
    }
}
