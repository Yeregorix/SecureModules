/*
 * Copyright (c) Forge Development LLC
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package net.minecraftforge.securemodules.test;

import net.minecraftforge.bootstrap.api.BootstrapEntryPoint;

public class BootstrapEntry implements BootstrapEntryPoint {
    @Override
    public void main(String... args) {
        try {
            var cls = Class.forName(args[0]);
            var mtd = cls.getDeclaredMethod(args[1]);
            mtd.invoke(null);
        } catch (Exception e) {
            sneak(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable, R> R sneak(Throwable e) throws E {
        throw (E)e;
    }
}
