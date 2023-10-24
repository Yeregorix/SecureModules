/*
 * Copyright (c) Forge Development LLC
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package net.minecraftforge.securemodules;

import java.io.IOException;
import java.lang.module.*;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.AllPermission;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.SecureClassLoader;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.Attributes;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SecureModuleClassLoader extends SecureClassLoader {
    // TODO: [SM] Introduce proper logging framework
    private static boolean DEBUG = Boolean.getBoolean("sm.debug");
    private static void log(String message) {
        if (DEBUG)
            System.out.println(message);
    }

    static {
        ClassLoader.registerAsParallelCapable();
        setupModularURLHandler();
    }

    @SuppressWarnings("removal")
    private static void setupModularURLHandler() {
        var handler = cpw.mods.cl.ModularURLHandler.INSTANCE;
        URL.setURLStreamHandlerFactory(handler);
        handler.findProviders(SecureModuleClassLoader.class.getModule().getLayer());
    }

    // TODO: [SM][Deprecation] Make private once cpw.mods.cl.ModuleClassLoader is deleted
    protected final Configuration configuration;
    private final List<ModuleLayer> parents;
    private final Map<String, ModuleReference> ourModules = new HashMap<>();
    private final Map<String, SecureModuleReference> ourModulesSecure = new HashMap<>();
    private final Map<String, ResolvedModule> packageToOurModules = new HashMap<>();
    private final Map<String, ClassLoader> packageToParentLoader = new HashMap<>();
    private final Map<ModuleReference, ModuleReader> moduleReaders = new ConcurrentHashMap<>();
    private final List<ClassLoader> allParentLoaders;
    private final Map<String, CodeSource> packageToCodeSource = new ConcurrentHashMap<>();
    private final boolean useCachedSignersForUnsignedCode;

    protected ClassLoader fallbackClassLoader = ClassLoader.getPlatformClassLoader();

    public SecureModuleClassLoader(String name, Configuration config, List<ModuleLayer> parentLayers) {
        this(name, config, parentLayers, null);
    }

    public SecureModuleClassLoader(String name, Configuration config, List<ModuleLayer> parentLayers, ClassLoader parent) {
        this(name, config, parentLayers, parent, false);
    }

    public SecureModuleClassLoader(String name, Configuration config, List<ModuleLayer> parentLayers, ClassLoader parent, boolean useCachedSignersForUnsignedCode) {
        super(name, parent);
        if (parent != null) // No need to be backwards compatible if they specify the parent
            fallbackClassLoader = null;

        this.configuration = config;
        this.useCachedSignersForUnsignedCode = useCachedSignersForUnsignedCode;
        this.parents = Stream.concat(parentLayers.stream(), List.of(ModuleLayer.boot()).stream()).distinct().toList(); // Old cpw code sends in duplicate layers Guard against
        this.allParentLoaders = this.parents.stream()
            .flatMap(p -> p.modules().stream())
            .map(Module::getClassLoader)
            .filter(cl -> cl != null)
            .distinct()
            .collect(Collectors.toCollection(ArrayList::new));

        // remove all that are covered by their parent loaders.
        var overlaping = new ArrayList<ClassLoader>();
        for (var loader : this.allParentLoaders) {
            do {
                loader = loader.getParent();
                if (loader != null && this.allParentLoaders.contains(loader))
                    overlaping.add(loader);
            } while (loader != null);
        }
        this.allParentLoaders.removeAll(overlaping);


        // Find all modules for this config, if the reference is our special Secure reference, we can define packages with security info.
        for (var module : config.modules()) {
            var ref = module.reference();
            this.ourModules.put(ref.descriptor().name(), ref);
            for (var pkg : ref.descriptor().packages())
                this.packageToOurModules.put(pkg, module);

            if (ref instanceof SecureModuleReference smr)
                this.ourModulesSecure.put(smr.descriptor().name(), smr);
            else
                log("[SecureModuleClassLoader] Insecure module: " + module);

        }

        if (DEBUG) {
            log("New ModuleClassLoader(" + name + ", @" + config.hashCode() + "[" + config + "])");
            for (var p : parents)
                log("  Parent @" + p.hashCode() + "[" + p.configuration() + "]");
        }

        // Gather packages in other classloaders that our modules read
        for (var module : config.modules()) {
            for (var other : module.reads()) {
                // If it reads the same layer as this, then we're good
                if (other.configuration() == this.configuration)
                    continue;

                var layer = this.parents.stream()
                    .filter(p -> p.configuration() == other.configuration())
                    .findFirst()
                    .orElse(null);


                if (layer == null)
                    throw new IllegalStateException("Could not find parent layer for module `" + other.name() + "` read by `" + module.name() + "`");


                var cl = layer == null ? null : layer.findLoader(other.name());
                if (cl == null)
                    cl = ClassLoader.getPlatformClassLoader();

                var descriptor = other.reference().descriptor();
                if (descriptor.isAutomatic()) {
                    for (var pkg : descriptor.packages())
                        setLoader(pkg, cl);
                } else {
                    for (var export : descriptor.exports()) {
                        if (!export.isQualified())
                            setLoader(export.source(), cl);
                        else if (config == other.configuration() && !export.targets().contains(module.name()))
                            setLoader(export.source(), cl);
                    }
                }
            }
        }
    }

    protected byte[] getClassBytes(ModuleReader reader, ModuleReference ref, String name) throws IOException {
        var read = reader.open(classToResource(name));
        if (!read.isPresent())
            return new byte[0];

        try (var is = read.get()) {
            return is.readAllBytes();
        }
    }

    protected byte[] maybeTransformClassBytes(byte[] bytes, String name, String context) {
        return bytes;
    }

    protected byte[] getMaybeTransformedClassBytes(String name, String context) throws ClassNotFoundException {
        Objects.requireNonNull(name);
        byte[] bytes = new byte[0];
        Throwable suppressed = null;
        try {
            var pkg = classToPackage(name);
            var module = this.packageToOurModules.get(pkg);
            if (module != null) {
                var ref = module.reference();
                try (var reader = ref.open()) {
                    return this.getClassBytes(reader, ref, name);
                }
            } else {
                var parent = this.packageToParentLoader.get(pkg);
                if (parent != null) {
                    try (var is = parent.getResourceAsStream(classToResource(name))) {
                        if (is != null)
                            bytes = is.readAllBytes();
                    }
                }
            }
        } catch (IOException e) {
            suppressed = e;
        }

        byte[] maybeTransformedBytes = maybeTransformClassBytes(bytes, name, context);
        if (maybeTransformedBytes.length == 0) {
            var e = new ClassNotFoundException(name);
            if (suppressed != null)
                e.addSuppressed(suppressed);
            throw e;
        }
        return maybeTransformedBytes;
    }

    /* ======================================================================
     * 				FIND FIRST RESOURCE
     * ======================================================================
     */

    @Override
    public URL getResource(String name) {
        Objects.requireNonNull(name);

        var url = super.getResource(name);
        if (url != null)
            return url;

        // The normal Modulear classloader { jdk.internal.loader.Loader.getResource(String) } delegates to the parent
        // But for some reason we set the parent to null
        // So manually look in the parent layers.
        for (var parent : this.allParentLoaders) {
            url = parent.getResource(name);
            if (url != null)
                return url;
        }

        return null;
    }

    @Override
    public URL findResource(String name) {
        Objects.requireNonNull(name);
        var pkg = pathToPackage(name);
        var module = this.packageToOurModules.get(pkg);
        if (module != null) {
            try {
                var url = findResource(module.name(), name);
                if (url != null && isOpenResource(name, url, module, pkg))
                    return url;
            } catch (IOException e) {
                // We didn't find shit!
            }
        } else {
            for (var moduleName : this.ourModules.keySet()) {
                try {
                    var url = findResource(moduleName, name);
                    if (url != null)
                        return url;
                } catch (IOException e) {
                    // Nope nothing in that module
                }
            }
        }

        return null;
    }

    @Override
    protected URL findResource(String moduleName, String name) throws IOException {
        Objects.requireNonNull(name);
        var module = moduleName == null ? null : this.ourModules.get(moduleName);
        if (module == null)
            return null; // Not one of our modules

        var reader = getModuleReader(module);
        var uri = reader.find(name);
        if (uri.isPresent())
            return uri.get().toURL();

        return null;
    }

    /* ======================================================================
     * 				FIND ALL RESOURCES
     * ======================================================================
     */

    @Override
    public Enumeration<URL> getResources(String name) throws IOException {
        var results = new ArrayList<Enumeration<URL>>();
        results.add(findResources(name));

        for (var parent : this.allParentLoaders) {
            results.add(parent.getResources(name));
        }

        return new Enumeration<>() {
            private Enumeration<Enumeration<URL>> itr = Collections.enumeration(results);
            private Enumeration<URL> current = itr.hasMoreElements() ? itr.nextElement() : null;

            @Override
            public boolean hasMoreElements() {
                return current != null && current.hasMoreElements();
            }

            @Override
            public URL nextElement() {
                var ret = current.nextElement();
                if (!current.hasMoreElements())
                    current = itr.hasMoreElements() ? itr.nextElement() : null;
                return ret;
            }
        };
    }

    @Override
    protected Enumeration<URL> findResources(String name) throws IOException {
        var pkg = pathToPackage(name);
        var module = packageToOurModules.get(pkg);
        List<URL> ret;

        if (module != null) {
            var url = findResource(module.name(), name);
            if (url != null && isOpenResource(name, url, module, pkg))
                ret = List.of(url);
            else
                ret = List.of();
        } else {
            ret = new ArrayList<>();
            for (var moduleName : this.ourModules.keySet()) {
                try {
                    var url = findResource(moduleName, name);
                    if (url != null)
                        ret.add(url);
                } catch (IOException e) {
                    // Nope nothing in that module
                }
            }
        }

        return Collections.enumeration(ret);
    }

    /* ======================================================================
     * 				FIND CLASSES
     * ======================================================================
     */

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        var pkg = classToPackage(name);
        var module = this.packageToOurModules.get(pkg);
        if (module == null)
            throw new ClassNotFoundException(name);

        var ref = module.reference();
        try (var reader = ref.open()) {
            return readerToClass(reader, ref, name);
        } catch (IOException e) {
            throw new ClassNotFoundException(name, e);
        }
    }

    @Override
    protected Class<?> findClass(String moduleName, String name) {
        var pkg = classToPackage(name);
        var module = this.packageToOurModules.get(pkg);
        if (module == null || !module.name().equals(moduleName))
            return null;

        var ref = module.reference();
        try (var reader = ref.open()) {
            return readerToClass(reader, ref, name);
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            var c = findLoadedClass(name);
            if (c == null) {
                var pkg = classToPackage(name);
                if (!pkg.isEmpty()) {
                    var module = this.packageToOurModules.get(pkg);

                    if (module != null)
                        c = findClass(module.name(), name);
                    else {
                        var parent = this.packageToParentLoader.get(pkg);
                        if (parent == null)
                            parent = fallbackClassLoader;

                        if (parent == null)
                            c = super.loadClass(name, false);
                        else
                            c = parent.loadClass(name);
                    }
                }
            }
            if (c == null)
                throw new ClassNotFoundException(name);

            if (resolve)
                resolveClass(c);

            return c;
        }
    }

    /* ======================================================================
     * 				INTERNAL IMPLEMENTATION CRAP
     * ======================================================================
     */
    private Class<?> readerToClass(ModuleReader reader, ModuleReference ref, String name) {
        byte[] bytes;
        try {
            bytes = getClassBytes(reader, ref, name);
        } catch (IOException e) {
            return sneak(e);
        }

        bytes = maybeTransformClassBytes(bytes, name, null);
        if (bytes.length == 0)
            return null;

        var data = this.ourModulesSecure.get(ref.descriptor().name());
        var url = ref.location().map(SecureModuleClassLoader::toURL).orElse(null);
        tryDefinePackage(name, data, url);

        var signers = data == null ? null : data.getCodeSigners(classToResource(name), bytes);
        return defineClass(name, bytes, 0, bytes.length, getCodeSource(name, url, signers));
    }

    @Override
    protected PermissionCollection getPermissions(CodeSource codesource) {
        var perms = new Permissions();
        // TODO: [SM] Gather permissions correctly
        // typically what we would do is gather the permissions like URLClassLoader does, but for now, fuck it.
        perms.add(new AllPermission());
        return perms;
    }

    private String classToResource(String name) {
        return name.replace('.', '/') + ".class";
    }

    private Package tryDefinePackage(String name, SecureModuleReference secure, URL base) throws IllegalArgumentException {
        var pkg = classToPackage(name);
        var ret = getDefinedPackage(pkg);
        if (ret == null) {
            synchronized (this) {
                ret = getDefinedPackage(pkg);
                if (ret == null) {
                    String path = pkg.replace('.', '/').concat("/");
                    String specTitle = null, specVersion = null, specVendor = null;
                    String implTitle = null, implVersion = null, implVendor = null;
                    URL sealBase = null;

                    if (secure != null) {
                        var main = secure.getMainAttributes();
                        var trusted = secure.getTrustedAttributes(path);
                        specTitle   = read(main, trusted, Attributes.Name.SPECIFICATION_TITLE);
                        specVersion = read(main, trusted, Attributes.Name.SPECIFICATION_VERSION);
                        specVendor  = read(main, trusted, Attributes.Name.SPECIFICATION_VENDOR);
                        implTitle   = read(main, trusted, Attributes.Name.IMPLEMENTATION_TITLE);
                        implVersion = read(main, trusted, Attributes.Name.IMPLEMENTATION_VERSION);
                        implVendor  = read(main, trusted, Attributes.Name.IMPLEMENTATION_VENDOR);
                        if ("true".equals(read(main, trusted, Attributes.Name.SEALED)))
                            sealBase = null; //TODO: [SM] Implement and test package sealing
                    }

                    ret = definePackage(pkg, specTitle, specVersion, specVendor, implTitle, implVersion, implVendor, sealBase);
                }
            }
        }
        return ret;
    }

    private static URL toURL(URI uri) {
        try {
            return uri.toURL();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static String read(Attributes main, Attributes trusted, Attributes.Name name) {
        if (trusted != null && trusted.containsKey(name)) return trusted.getValue(name);
        return main == null ? null : main.getValue(name);
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable, R> R sneak(Exception exception) throws E {
        throw (E)exception;
    }

    private static String pathToPackage(String name) {
        int idx = name.lastIndexOf('/');
        if (idx == -1 || idx == name.length() - 1)
            return "";
        return name.substring(0, idx).replace('/', '.');
    }

    private static String classToPackage(String name) {
        int idx = name.lastIndexOf('.');
        if (idx == -1 || idx == name.length() - 1)
            return "";
        return name.substring(0, idx);
    }

    private boolean setLoader(String pkg, ClassLoader loader) {
        var existing = this.packageToParentLoader.putIfAbsent(pkg, loader);
        if (existing != null && existing != loader)
            throw new IllegalStateException("Package " + pkg + " cannot be imported from multiple loaders");
        return existing == null;
    }


    private static boolean isOpenResource(String name, URL url, ResolvedModule module, String pkg) {
        if (name.endsWith(".class") || url.toString().endsWith("/"))
            return true;

        var desc = module.reference().descriptor();
        if (desc.isOpen() || desc.isAutomatic())
            return true;

        for (var opens : desc.opens()) {
            if (!opens.source().equals(pkg))
                continue;

            return !opens.isQualified();
        }
        return false;
    }

    private ModuleReader getModuleReader(ModuleReference reference) {
        return this.moduleReaders.computeIfAbsent(reference, k -> {
            try {
                return reference.open();
            } catch (IOException e) {
                return NOOP_READER;
            }
        });
    }

    private static ModuleReader NOOP_READER = new ModuleReader() {
        @Override
        public Optional<URI> find(String name) throws IOException {
            return Optional.empty();
        }

        @Override
        public Stream<String> list() throws IOException {
            return Stream.empty();
        }

        @Override
        public void close() throws IOException {
        }
    };

    // TODO: [SM][Deprecation] Make private once cpw.mods.cl.ModuleClassLoader is deleted
    protected String classNameToModuleName(String name) {
        var module = this.packageToOurModules.get(classToPackage(name));
        return module == null ? null : module.name();
    }

    private static final Certificate[] EMPTY_CERTS = new Certificate[0];
    /*
     * All classes in the same package must have the exact same signers.
     * The JRE enforces this in ClassLoader.checkCerts
     * However in Minecraft world we expect to see dynamic classes
     * and modified classes in the same package as clean classes.
     * So what we do is capture the FIRST codesource we see in the package.
     * Then use that for all other classes from then on.
     * However, we should also log when signatures are missing. So that
     * consumers can know.
     */
    private CodeSource getCodeSource(String name, URL url, CodeSigner[] signers) {
        var clsCS = new CodeSource(url, signers);
        if (!this.useCachedSignersForUnsignedCode)
            return clsCS;

        var pkgCS = this.packageToCodeSource.computeIfAbsent(classToPackage(name), pkg -> clsCS);
        if (DEBUG && pkgCS != clsCS) {
            var pCerts = or(pkgCS.getCertificates(), EMPTY_CERTS);
            var cCerts = or(clsCS.getCertificates(), EMPTY_CERTS);
            if (pCerts.length == 0 && cCerts.length == 0)
                return pkgCS;

            boolean found = false;
            for (var cert : cCerts) {
                found = false;
                for (var pcert : pCerts) {
                    if (cert.equals(pcert)) {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    log("Class " + name + " has extra certificate: " + getFingerprint(cert));
            }
            for (var pcert : pCerts) {
                found = false;
                for (var cert : cCerts) {
                    if (pcert.equals(cert)) {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    log("Class " + name + " has missing certificate: " + getFingerprint(pcert));
            }
        }
        return pkgCS;
    }

    private static <R> R or(R left, R right) {
        return left != null ? left : right;
    }

    private static String getFingerprint(Certificate cert) {
        if (cert == null)
            return "NULL";

        try {
            var md = MessageDigest.getInstance("SHA-1");
            md.update(cert.getEncoded());
            var digest = md.digest();
            var ret = new StringBuilder(2 * digest.length);
            for (var c : digest) {
                var h = c & 0x0F;
                ret.append(h < 10 ? '0' + h : 'A' + h);
                h = (c & 0xF0) >> 4;
                ret.append(h < 10 ? '0' + h : 'A' + h);
            }
            return ret.toString();
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        }
    }
}
