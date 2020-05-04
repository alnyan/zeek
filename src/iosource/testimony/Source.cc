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
	props.path = path;
	props.is_live = is_live;
    curr_packet = NULL;
	}

void TestimonySource::Open()
	{
	OpenLive();
	}

void TestimonySource::Close()
	{
    //if ( curr_block )
    //    testimony_return_block(td, curr_block);

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

//bool TestimonySource::FetchNextBlock()
//    {
//    int res;
//
//    res = testimony_get_block(td, 1000, &curr_block);
//    if ( res == 0 && ! curr_block )
//        return true;
//
//    if ( res < 0 )
//        {
//        Error(fmt("testimony_get_block: %s, %s", testimony_error(td), strerror(-res)));
//        Close();
//        return false;
//        }
//
//    testimony_iter_reset(td_iter, curr_block);
//    return true;
//    }

//bool TestimonySource::ExtractNextPacketInternal(Packet* pkt)
//	{
    //int res;

    //if ( curr_block )
    //    {
    //    // Obtain next packet from current block
    //    curr_packet = testimony_iter_next(td_iter);

    //    // If block is exhausted, return it back
    //    if ( ! curr_packet )
    //        {
    //        res = testimony_return_block(td, curr_block);
    //        curr_block = NULL;

    //        if ( res < 0 )
    //            {
    //            Error(fmt("testimony_return_block: %s, %s", testimony_error(td), strerror(-res)));
    //            Close();
    //            return false;
    //            }
    //        }
    //    }

    //// If no block is being processed now, load one
    //if ( ! curr_block )
    //    {
    //    if ( ! FetchNextBlock() )
    //        {
    //        return false;
    //        }

    //    // Likely a timeout
    //    if ( ! curr_block )
    //        return false;

    //    // Try again
    //    return ExtractNextPacketInternal(pkt);
    //    }

//	}

bool TestimonySource::ExtractNextPacket(Packet* pkt)
    {
    if ( ! queue.empty() )
        {
        printf("Get from queue\n");
        curr_packet = queue.front();
        queue.pop();

        curr_timeval.tv_sec = curr_packet->tp_sec;
        curr_timeval.tv_usec = curr_packet->tp_nsec / 1000;
	    pkt->Init(props.link_type, &curr_timeval, curr_packet->tp_snaplen, curr_packet->tp_len, (const u_char *) curr_packet + curr_packet->tp_mac);

        return true;
        } else {
        const tpacket_block_desc *block = NULL;
        const tpacket3_hdr *packet;

        int res = testimony_get_block(td, 100, &block);
        if ( res == 0 && !block ) {
            // Timeout
            return false;
        }

        if ( res < 0 )
            {
            Error(fmt("testimony_get_block: %s, %s", testimony_error(td), strerror(-res)));
            Close();
            return false;
            }

        int cnt = 0;

        testimony_iter_reset(td_iter, block);
        while ( (packet = testimony_iter_next(td_iter)) )
            {
            // Queue the packet
            char *data = new char[packet->tp_len + packet->tp_mac];
            memcpy(data, packet, packet->tp_len + packet->tp_mac);
            queue.push((tpacket3_hdr *) data);

            ++stats.received;
            ++cnt;
            stats.bytes_received += packet->tp_len;
            }

        testimony_return_block(td, block);
        printf("Got %u to queue\n", cnt);

        // Try again
        return ExtractNextPacket(pkt);
        }
    }

void TestimonySource::DoneWithPacket()
	{
    if ( curr_packet )
        {
        delete curr_packet;
        curr_packet = NULL;
        printf("Release packet\n");
        }
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
