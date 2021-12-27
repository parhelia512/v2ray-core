package tun

type in6_addr struct {
	addr [16]byte
}

type in6_ifreq struct {
	ifr6_addr      in6_addr
	ifr6_prefixlen uint32
	ifr6_ifindex   uint32
}
