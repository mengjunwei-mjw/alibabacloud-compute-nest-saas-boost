package org.example.common.constant;

public enum StorageMethod {
    /**
     * storage in local file system
     */
    LOCAL("local"),

    /**
     * storage in aliyun oss
     */
    OSS("oss"),

    /**
     * storage in both local file system and aliyun oss
     */
    BOTH("both");

    private final String method;

    StorageMethod(String method) {
        this.method = method;
    }

    public String getMethod() {
        return method;
    }

    @Override
    public String toString() {
        return name();
    }
}
