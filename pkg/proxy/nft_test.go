//go:build linux

package proxy

import (
	"bytes"
	"net"
	"testing"
)

func TestConcatPortKey(t *testing.T) {
	tests := []struct {
		name  string
		ip    string
		proto byte
		port  uint16
		want  []byte
	}{
		{
			name:  "tcp/80",
			ip:    "10.0.0.1",
			proto: 6,
			port:  80,
			want:  []byte{10, 0, 0, 1, 6, 0, 0, 0, 0, 80, 0, 0},
		},
		{
			name:  "udp/53",
			ip:    "192.168.1.10",
			proto: 17,
			port:  53,
			want:  []byte{192, 168, 1, 10, 17, 0, 0, 0, 0, 53, 0, 0},
		},
		{
			name:  "high port BE",
			ip:    "172.16.0.5",
			proto: 6,
			port:  50000, // 0xC350 → bytes 195, 80
			want:  []byte{172, 16, 0, 5, 6, 0, 0, 0, 195, 80, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := concatPortKey(net.ParseIP(tt.ip), tt.proto, tt.port)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("concatPortKey(%s, %d, %d) = %v, want %v",
					tt.ip, tt.proto, tt.port, got, tt.want)
			}
			if len(got) != 12 {
				t.Errorf("expected 12-byte key, got %d bytes", len(got))
			}
		})
	}
}
