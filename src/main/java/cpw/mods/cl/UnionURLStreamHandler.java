/*
 * Copyright (c) Forge Development LLC
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package cpw.mods.cl;

import cpw.mods.niofs.union.UnionPath;

import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.function.Function;

/**
 * UnionFileSystem implements this as a base Java provider normally now.
 */
@Deprecated(forRemoval = true)
public class UnionURLStreamHandler implements ModularURLHandler.IURLProvider {
    @Override
    public String protocol() {
        return "union";
    }

    @Override
    public Function<URL, InputStream> inputStreamFunction() {
        return u-> {
            try {
                if (Paths.get(u.toURI()) instanceof UnionPath upath) {
                    return upath.buildInputStream();
                } else {
                    throw new IllegalArgumentException("Invalid Path "+u.toURI()+" at UnionURLStreamHandler");
                }
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        };
    }
}
