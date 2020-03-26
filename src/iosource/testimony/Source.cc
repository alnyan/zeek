// See the file  in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Source.h"
#include "iosource/Packet.h"
#include "iosource/BPF_Program.h"

#include <unistd.h>

#include "Event.h"

using namespace iosource::testimony;

TestimonySource::~TestimonySource()
	{
	Close();
	}

TestimonySource::TestimonySource(const std::string& path, bool is_live)
	{
    printf("Create socket!\n");
	props.path = path;
	props.is_live = is_live;
    curr_block = NULL;
    curr_packet = NULL;
	}

void TestimonySource::Open()
	{
	OpenLive();
	}

void TestimonySource::Close()
	{
    if ( curr_block )
        testimony_return_block(td, curr_block);

    testimony_close(td);

	Closed();
	}

void TestimonySource::OpenLive()
	{
    int res;

    res = testimony_connect(&td, props.path.c_str());
    if ( res < 0 )
        {
        Error(fmt("testimony_connect: %s", strerror(-res)));
        return;
        }

    res = testimony_init(td);
    if ( res < 0 )
        {
        Error(fmt("testimony_init: %s, %s", testimony_error(td), strerror(-res)));
        return;
        }

    testimony_iter_init(&td_iter);

	props.selectable_fd = -1;

	props.link_type = DLT_EN10MB;
	props.is_live = true;

	Opened(props);
	}

bool TestimonySource::FetchNextBlock()
    {
    int res;

    res = testimony_get_block(td, 1000, &curr_block);
    if ( res == 0 && ! curr_block )
        return true;

    if ( res < 0 )
        {
        Error(fmt("testimony_get_block: %s, %s", testimony_error(td), strerror(-res)));
        Close();
        return false;
        }

    testimony_iter_reset(td_iter, curr_block);
    return true;
    }

bool TestimonySource::ExtractNextPacketInternal(Packet* pkt)
	{
    int res;

    if ( curr_block )
        {
        // Obtain next packet from current block
        curr_packet = testimony_iter_next(td_iter);

        // If block is exhausted, return it back
        if ( ! curr_packet )
            {
            res = testimony_return_block(td, curr_block);
            curr_block = NULL;

            if ( res < 0 )
                {
                Error(fmt("testimony_return_block: %s, %s", testimony_error(td), strerror(-res)));
                Close();
                return false;
                }
            }
        }

    // If no block is being processed now, load one
    if ( ! curr_block )
        {
        if ( ! FetchNextBlock() )
            {
            return false;
            }

        // Likely a timeout
        if ( ! curr_block )
            return false;

        // Try again
        return ExtractNextPacketInternal(pkt);
        }

    const uint8_t *data = testimony_packet_data(curr_packet);
    curr_timeval.tv_sec = curr_packet->tp_sec;
    curr_timeval.tv_usec = curr_packet->tp_nsec / 1000;

	pkt->Init(props.link_type, &curr_timeval, curr_packet->tp_snaplen, curr_packet->tp_len, data);

	++stats.received;
	stats.bytes_received += curr_packet->tp_len;

    return true;
	}

bool TestimonySource::ExtractNextPacket(Packet* pkt)
    {
    return ExtractNextPacketInternal(pkt);
    }

void TestimonySource::DoneWithPacket()
	{
	// Nothing to do.
	}

bool TestimonySource::PrecompileFilter(int index, const std::string& filter)
	{
    // Nothing to do. Packet filters are configured on
    // testimony daemon side
    return true;
	}

bool TestimonySource::SetFilter(int index)
	{
	return true;
	}

void TestimonySource::Statistics(Stats* s)
	{
    s->received = stats.received;
    s->bytes_received = stats.bytes_received;

    // TODO: get this information from the daemon
    s->link = stats.received;
    s->dropped = 0;
	}

iosource::PktSrc* TestimonySource::Instantiate(const std::string& path, bool is_live)
	{
	return new TestimonySource(path, is_live);
	}
