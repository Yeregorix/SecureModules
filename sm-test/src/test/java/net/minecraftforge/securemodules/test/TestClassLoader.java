/*
 * Copyright (c) Forge Development LLC
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package net.minecraftforge.securemodules.test;

import java.lang.module.ModuleFinder;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import cpw.mods.jarhandling.SecureJar;
import net.minecraftforge.bootstrap.Bootstrap;
import net.minecraftforge.securemodules.SecureModuleClassLoader;
import net.minecraftforge.securemodules.SecureModuleFinder;

import static org.junit.jupiter.api.Assertions.*;
import static net.minecraftforge.securemodules.test.TestSecureJarLoading.hash;
import static net.minecraftforge.securemodules.test.TestSecureJarLoading.FINGERPRINT;

public class TestClassLoader {
    public static class Boot extends Bootstrap {
        public Boot() {}
        public Boot(String name) throws Exception {
            this.start(TestClassLoader.class.getName(), name);
        }
    };

    private static void boot(String name) throws Exception {
        new Boot(name);
    }

    private static ClassLoader setup(String name) throws Exception {
        return setup(name, false);
    }

    private static ClassLoader setup(String name, boolean propagates) throws Exception {
        var path = Paths.get("src/test/resources/" + name + ".jar");
        var jar = SecureJar.from(path);
        return setup(jar, propagates);
    }

    private static ClassLoader setup(SecureJar jar, boolean propagates) throws Exception {
        assertEquals("test", jar.moduleDataProvider().name(), "Incorrect module name");

        var layer = TestClassLoader.class.getModule().getLayer();
        var cfg = layer.configuration().resolveAndBind(SecureModuleFinder.of(jar), ModuleFinder.of(), List.of("test"));

        var cl = new SecureModuleClassLoader("MODULE-CLASSLOADER", null, cfg, List.of(layer), List.of(), propagates);
        var layer2 = layer.defineModules(cfg, mod -> cl);

        return layer2.findModule("test").get().getClassLoader();
    }

    private static Class<?> getClass(String name, ClassLoader cl) throws Exception {
        var cls = Class.forName(name, false, cl);
        assertNotNull(cls, "Failed to find " + name);
        assertEquals("test", cls.getModule().getName(), "Invalid Module");
        return cls;
    }

    @Test // All files are signed
    void testSignedr() throws Exception {
        boot("testSignedBoot");
    }
    public static void testSignedBoot() throws Exception {
        var cl = setup("signed");
        var signed = getClass("test.Signed", cl);
        var signers = signed.getSigners();
        assertNotNull(signers, "Missing code signers");
        assertEquals(1, signers.length, "Expected only one code");
        var cert = (Certificate)signers[0];
        assertEquals(FINGERPRINT, hash(cert.getEncoded()), "Unexpected Certificate fingerprint");
    }

    @Test // Nothing is signed
    void testUnsigned() throws Exception {
        boot("testUnsignedBoot");
    }
    public static void testUnsignedBoot() throws Exception {
        var cl = setup("unsigned");
        for (var name : new String[] {"test.Signed", "test.UnSigned"}) {
            var cls = getClass(name, cl);
            var signers = cls.getSigners();
            assertNull(signers, "Unexpected code signers for " + name);
        }
    }

    /**
     * Because we intentionally work in a environment where classes are generated on the fly.
     * When asked to, we have to propagate any signing certs for every class in the package.
     * Because the base ClassLoader verifies that all certs are shared.
     *
     * So verify that classes in the same package get the same signatures
     */
    @Test // Contained a signed file, as well as a unsigned file.
    void testPartialPropogates() throws Exception {
        boot("testPartialPropogatesBoot");
    }
    public static void testPartialPropogatesBoot() throws Exception {
        var cl = setup("partial", true);
        // If signed code is loaded first, then unsigned code will get certs.
        for (var name : new String[] {"test.Signed", "test.UnSigned"}) {
            var cls = getClass(name, cl);
            var signers = cls.getSigners();
            assertNotNull(signers, "Missing code signers array for " + name);
            assertEquals(1, signers.length, "Expected only one code signer for " + name);
            var cert = (Certificate)signers[0];
            assertEquals(FINGERPRINT, hash(cert.getEncoded()), "Unexpected Certificate fingerprint for " + name);
        }

        // Now test that we propagate MISSING certs if UnSigned code is loaded first
        cl = setup("partial", true);
        for (var name : new String[] {"test.UnSigned", "test.Signed"}) {
            var cls = getClass(name, cl);
            var signers = cls.getSigners();
            assertNull(signers, "Unexpected signers for " + name);
        }
    }

    /**
     * The normal Java ClassLoader verifies that all classes in a package have the same certificates.
     * If they do not we expect to get an error
     */
    @Test // Contained a signed file, as well as a unsigned file.
    void testPartialDoesntPropogate() throws Exception {
        boot("testPartialDoesntPropogateBoot");
    }
    public static void testPartialDoesntPropogateBoot() throws Exception {
        // Unsigned code first
        var cl = setup("partial");
        var cls = getClass("test.UnSigned", cl);
        assertNull(cls.getSigners(), "Unexpected code signers for test.UnSigned");
        assertThrows(SecurityException.class, () -> Class.forName("test.Signed", false, cl));


        // Unsigned code first
        var cl2 = setup("partial");
        cls = getClass("test.Signed", cl2);
        assertNotNull(cls.getSigners(), "Expected code signer for test.Signed");
        assertThrows(SecurityException.class, () -> Class.forName("test.UnSigned", false, cl2));
    }

    /**
     * So, in theory we should detect and throw some kind of exception if there is tampered jar being loaded.
     * However current behavior is to just mark it as invalid and still execute the code.
     * This sounds like a horrible security issue. But whatever
     *
     * In base java, signatures are verified by JarFile when the InputStream of an entry is read.
     *
     * For now, it just loads as if the code was unsigned, but we track it internally as 'INVALID'
     *
     * TODO: [SM][Union] Teach Union to verify signatures when reading
     */
    @Test // Has a file that is signed, but modified
    void testTampered() throws Exception {
        boot("testTamperedBoot");
    }
    public static void testTamperedBoot() throws Exception {
        var path = Paths.get("src/test/resources/invalid.jar");
        var jar = SecureJar.from(path);
        var cl = setup(jar, false);

        var cls = getClass("test.Signed", cl);
        assertNull(cls.getSigners(), "Unexpected code signers");

        assertEquals(SecureJar.Status.INVALID, jar.getFileStatus("test/Signed.class"), "Incorrect file status");
    }

    /**
     * Make sure that we can validate the Multi-Release jar's contents
     */
    @Test // Multi-Release jar is signed
    void testMultiRelease() throws Exception {
        boot("testMultiReleaseBoot");
    }
    public static void testMultiReleaseBoot() throws Exception {
        var cl = setup("multirelease");
        var cls = getClass("test.Signed", cl);
        var signers = cls.getSigners();
        assertNotNull(signers, "Missing code signers");
        assertEquals(1, signers.length, "Expected only one code");
        var cert = (Certificate)signers[0];
        assertEquals(FINGERPRINT, hash(cert.getEncoded()), "Unexpected Certificate fingerprint");
        var marker = (String)cls.getDeclaredMethod("marker").invoke(null);
        assertEquals("Java 9", marker, "Invalid class loaded");
    }

    /**
     * Our class loader supports adding version information to a package and using modules
     * Unfortunately this is mutually exclusive in base java implementations for some reason.
     * Causing package info classes to not load, so make sure we properly load them.
     */
    @Test
    void testPackageInfo() throws Exception {
        boot("testPackageInfoBoot");
    }
    public static void testPackageInfoBoot() throws Exception {
        var cl = setup("package-info");
        var cls = getClass("test.UnSigned", cl);
        var ann = cls.getPackage().getAnnotations();
        assertNotNull(ann, "Annotations array is null");
        assertEquals(1, ann.length, "Unexpected number of package annotations");

        var annCls = getClass("test.RuntimeAnnotation", cl);
        assertEquals(annCls, ann[0].annotationType(), "Unexpected annotation type");


        var info = getClass("test.package-info", cl);
        assertEquals(cls.getModule(), info.getModule(), "Mismatched modules");
    }

    @Test
    void testInterruption() throws Exception {
        boot("testInterruptionBoot");
    }
    public static void testInterruptionBoot() throws Exception {
        var cl = setup("signed");

        CompletableFuture<Void> future = new CompletableFuture<>();
        new Thread(() -> {
            try {
                Thread.currentThread().interrupt();
                getClass("test.Signed", cl);
                future.complete(null);
            } catch (Exception e) {
                future.completeExceptionally(e);
            }
        }).start();

        future.join();
    }
}
