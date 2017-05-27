#pragma once

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN

namespace SuspendCore
{
	class CSuspendCore
	{
		public:
			void SuspendThread(DWORD dwThreadId);
	};
}

