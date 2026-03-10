#pragma once

#include "Network/Channel.h"
void senderGetLatency(osuCrypto::Channel &chl);

void recverGetLatency(osuCrypto::Channel &chl);

void senderSync(osuCrypto::Channel &chl);

void recverSync(osuCrypto::Channel &chl);
