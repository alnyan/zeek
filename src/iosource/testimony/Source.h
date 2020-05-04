// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "../PktSrc.h"

extern "C" {
#include <testimony.h>
}

#include <queue>
#include <sys/types.h> // for u_char

namespace iosource {
namespace testimony {

class TestimonySource : public iosource::PktSrc {
public:
	TestimonySource(const std::string& path, bool is_live);
	~TestimonySource() override;

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	void Open() override;
	void Close() override;
	bool ExtractNextPacket(Packet* pkt) override;
	void DoneWithPacket() override;
	bool PrecompileFilter(int index, const std::string& filter) override;
	bool SetFilter(int index) override;
	void Statistics(Stats* stats) override;

private:
	void OpenLive();
	//bool ExtractNextPacketInternal(Packet* pkt);
    //bool FetchNextBlock();

    ::testimony td;
    ::testimony_iter td_iter;
    timeval curr_timeval;
    tpacket3_hdr *curr_packet;
    std::queue<tpacket3_hdr *> queue;

	Properties props;
	Stats stats;
};

}
}
