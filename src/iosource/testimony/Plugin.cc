// See the file  in the main distribution directory for copyright.

#include "Source.h"

#include "plugin/Plugin.h"
#include "iosource/Component.h"

namespace plugin {
namespace Zeek_Testimony {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::iosource::PktSrcComponent("TestimonyReader", "testimony", ::iosource::PktSrcComponent::LIVE, ::iosource::testimony::TestimonySource::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::Testimony";
		config.description = "Packet acquisition from Google Testimony Unix socket";
		return config;
		}
} plugin;

}
}

