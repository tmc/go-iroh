package socket

// IPv4ArrivalSupported reports whether this platform reports the IPv4
// destination of a received datagram in a form parsePacketInfo understands.
// Tests that expect an IPv4 reply to leave from the arrival address skip
// where it does not: the BSDs report the destination through IP_RECVDSTADDR,
// which cannot be paired with an IPv4 source on send, so a reply there leaves
// from the address the kernel picks, as it did before the table.
const IPv4ArrivalSupported = sysIPPktinfo >= 0
