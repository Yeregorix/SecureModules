module net.minecraftforge.securemodules.test {
    requires cpw.mods.securejarhandler; // TODO: [SM][Deprecation] Remove CPW compatibility

    requires jdk.unsupported;
    requires java.base;
    requires org.junit.jupiter.api;
    requires org.objectweb.asm;
    requires org.objectweb.asm.tree;
    requires net.minecraftforge.unsafe;

    opens net.minecraftforge.securemodules.test to org.junit.platform.commons;
}