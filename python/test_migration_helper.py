import ipaddress
import unittest

from migration_helper import ip_mapper, IpMapping


test_ips = [
    IpMapping("910540000000001", ipaddress.IPv4Address("192.168.151.2")),
    IpMapping("910540000000002", ipaddress.IPv4Address("192.168.151.3")),
    IpMapping("910540000000252", ipaddress.IPv4Address("192.168.152.254")),
    IpMapping("910540000000253", ipaddress.IPv4Address("192.168.152.2")),
    IpMapping("910540000000254", ipaddress.IPv4Address("192.168.152.3")),
    IpMapping("910540000000255", ipaddress.IPv4Address("192.168.152.4")),
    IpMapping("910540000000256", ipaddress.IPv4Address("192.168.152.5")),
]

result_ips = [
    IpMapping("910540000000001", ipaddress.IPv4Address("10.45.1.1")),
    IpMapping("910540000000002", ipaddress.IPv4Address("10.45.1.2")),
    IpMapping("910540000000252", ipaddress.IPv4Address("10.45.1.252")),
    IpMapping("910540000000253", ipaddress.IPv4Address("10.45.1.253")),
    IpMapping("910540000000254", ipaddress.IPv4Address("10.45.1.254")),
    IpMapping("910540000000255", ipaddress.IPv4Address("10.45.1.255")),
    IpMapping("910540000000256", ipaddress.IPv4Address("10.45.2.0")),
]

new_base = ipaddress.ip_interface("10.45.1.0/16")


class IpMapperTest(unittest.TestCase):
    def test(self):
        for original, result in zip(test_ips, result_ips):
            # Sanity check the test data is correct
            self.assertEqual(original.imsi, result.imsi)

            remapped_ip = ip_mapper("91054000", new_base, original)
            self.assertEqual(remapped_ip, result)
