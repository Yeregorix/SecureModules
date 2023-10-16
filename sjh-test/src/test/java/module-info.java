module net.minecraftforge.securejarhandler.test {
    requires cpw.mods.securejarhandler;
    requires jdk.unsupported;
    requires java.base;
    requires org.junit.jupiter.api;
    requires org.objectweb.asm;
    requires org.objectweb.asm.tree;
    requires net.minecraftforge.unsafe;
    opens net.minecraftforge.securejarhandler.test to org.junit.platform.commons;
}