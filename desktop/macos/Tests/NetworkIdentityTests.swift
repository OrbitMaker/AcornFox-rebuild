import Foundation
import Virtualization

@main struct NetworkIdentityTests {
    static func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws { if try !value() { throw NSError(domain: label, code: 1) } }
    static func main() throws {
        let firstID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let first = try VMConfigurationFactory.makeNetwork(instanceID: firstID)
        let again = try VMConfigurationFactory.makeNetwork(instanceID: firstID)
        let second = try VMConfigurationFactory.makeNetwork(instanceID: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!)
        try require(first.macAddress.string == "b6:03:53:ab:b8:79", "stable versioned MAC fixture")
        try require(first.macAddress.string == again.macAddress.string, "same instance MAC survives configuration rebuild")
        try require(first.macAddress.string != second.macAddress.string, "different instances have distinct MAC fixtures")
        try require(first.macAddress.isLocallyAdministeredAddress && first.macAddress.isUnicastAddress && !first.macAddress.isMulticastAddress, "local unicast address flags")
        let byte = UInt8(first.macAddress.string.split(separator: ":")[0], radix: 16)!
        try require(byte & 0x03 == 0x02 && first.macAddress.string.split(separator: ":").count == 6, "six bytes with IEEE local/unicast bits")
        try require(first.attachment is VZNATNetworkDeviceAttachment, "NAT attachment retained")
        print("PASS deterministic per-instance MAC; distinct fixtures; local/unicast bits; NAT unchanged")
        let root = URL(fileURLWithPath: "/private/tmp/acornfox-network-identity-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        var preparer: DiskPreparer? = try DiskPreparer(state: PrivateState(root: root))
        let savedID = preparer!.instanceID
        let savedMAC = try VMConfigurationFactory.makeNetwork(instanceID: savedID).macAddress.string
        preparer = nil
        let reopened = try DiskPreparer(state: PrivateState(root: root))
        try require(reopened.instanceID == savedID, "persisted instance UUID")
        try require(try VMConfigurationFactory.makeNetwork(instanceID: reopened.instanceID).macAddress.string == savedMAC, "reopened instance retains network identity")
        print("PASS persisted verified instance UUID reopens with identical network MAC")
        print("ALL NETWORK IDENTITY TESTS PASSED")
    }
}
