// SPDX-FileCopyrightText: 2002-2024 PCSX2 Dev Team
// SPDX-License-Identifier: LGPL-3.0+

/* A reference client implementation for interfacing with PINE is available
 * here: https://code.govanify.com/govanify/pine/ */

#pragma once

namespace PINEServer {
bool IsInitialized();
int GetSlot();

bool Initialize(u16 slot);
void Deinitialize();
void Poll();
} // namespace PINEServer
