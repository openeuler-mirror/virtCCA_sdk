# 全盘加密<a name="ZH-CN_TOPIC_0000002184143736"></a>

全盘加密（Full Disk Encryption, FDE ）是一种通过加密整个磁盘分区来保护敏感信息的安全技术。在非机密计算环境中，FDE通常基于LUKS（Linux 统一密钥设置）和用户提供的密钥实现。然而，在virtCCA这类基于TrustZone的机密计算架构中，加密密钥需要通过认证服务（attestation service） 安全获取，而非直接依赖用户输入。

本节描述将FDE与华为virtCCA集成的实现步骤，主要分为三个阶段。

1.  构建本地验证器的用户环境，并生成镜像加密的密钥文件。
2.  使用密钥文件创建加密的CVM镜像，并将FDE组件安装到其初始内存文件系统（initramfs）中。
3.  通过early-boot FDE流程启动基于加密镜像的CVM。

**图 1**  架构图<a name="fig1550770122210"></a>
![](../images/架构图.png "images/架构图")

## 准备本地验证器与加密密钥<a name="section283022992414"></a>

FDE代码位于目录“FDE\_DIR=virtCCA\_sdk/attestation/full-disk-encryption/grub-boot“中。

```
cd ${FDE_DIR}/attestation
sh pre-fde.sh
```

-   脚本pre-fde.sh会检查认证所需的client和server是否存在。若不存在，则会重新编译virtCCA\_sdk/attestation/sdk和virtCCA\_sdk/attestation/samples，并将认证应用复制到当前目录。
-   脚本pre-fde.sh还会检查镜像加密的密钥文件是否存在，若不存在，则会在当前目录重新生成密钥文件。

## 创建加密的CVM镜像<a name="section13865173872814"></a>

构建并验证openEuler 24.03 cVM镜像。

>![](../public_sys-resources/icon-note.gif) **说明：**
>-   -i ：表示cVM镜像，参考[制作qcow2 镜像](../nottoctopics/zh-cn_topic_0000002152492552.md)获取。
>-   -g ：表示cVM镜像组件（grub镜像、grub.cfg 文件、Kernel镜像、initramfs镜像）的度量基线值，可参考[制作qcow2 镜像](../nottoctopics/zh-cn_topic_0000002152492552.md)的hash.json文件。
>-   -o ：可选参数，用于指定cVM镜像的输出路径。

```
cd ${FDE_DIR}/image
sh create-fde-image.sh -i <guest image> -g <reference measurements> -o <output image>
```

-   脚本create\_fde\_image.sh将使用加密密钥加密根文件系统，它会创建一个名为fde的dracut模块，并将FDE相关组件例如认证应用server、FDE代理fde-agent.sh和加密工具cryptsetup安装到initramfs中。内核启动参数会追加root=/dev/mapper/encroot（表示加密的根文件系统分区），同时更新“/etc/fstab“以自动挂载加密根分区。
-   由于GRUB配置文件（如 grub.cfg）和initramfs镜像被修改，因此脚本会更新参考度量值（如 hash.json）并将其复制到“$\{FDE\_DIR\}/attestation“目录用于认证。
-   默认输出镜像为$\{FDE\_DIR\}/image/virtcca-cvm-openeuler-24.03-encrypted.qcow2，其磁盘分区如下。

    ![](../images/250219155502777.png)

    >![](../public_sys-resources/icon-note.gif) **说明：**
    >加密后的根分区/dev/vda2通过LUKS保护。

## 基于early-boot FDE启动cVM<a name="section591018993410"></a>

当cVM启动进入initramfs阶段时，终端会输出IP地址和端口如下图所示。

![](../images/zh-cn_image_0000002184736806.png)

1.  用户根据cVM的输出日志，在宿主机terminal中执行如下命令，用来保存IP地址和端口号。

    ```
    export IP_ADDR=192.168.122.150
    export PORT=7220
    ```

2.  initramfs中的脚本fde-agent.sh会自动执行如下命令, 该命令会通过TMM服务接口获取度量报告（attestation token）， 并等待client的请求。

    ```
    /usr/bin/server -i ${IP_ADDR} -p $PORT -k
    ```

3.  client向server发起请求，获取度量报告， 在本地验证通过后， 再将加密密钥发送到server。

    >![](../public_sys-resources/icon-note.gif) **说明：**
    >其中-m参数请参见[远程证明](../nottoctopics/zh-cn_topic_0000002187807873.md)获取cVM基线度量值。

    ```
    cd ${FDE_DIR}/attestation
    ```

    client 命令的详细使用说明请参考：

    https://gitee.com/confidential-computing-personal/virtCCA\_sdk/blob/master/attestation/full-disk-encryption/grub-boot/README.md

4.  脚本fde-agent.sh会使用加密密钥运行cryptsetup解密根文件系统并挂载。
5.  启动完成后， 在cVM中执行**lsblk**，可看到挂载的加密存储设备encroot。

    ![](../images/zh-cn_image_0000002184443478.png)
