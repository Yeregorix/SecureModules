/*
 * Copyright (c) Forge Development LLC
 * SPDX-License-Identifier: LGPL-2.1-only
 */

module net.minecraftforge.securemodules.jmh {
    requires cpw.mods.securejarhandler; // TODO: [SM][Deprecation] Remove CPW compatibility
    requires jmh.core;
    requires jdk.unsupported; // Needed by jmh.core
}