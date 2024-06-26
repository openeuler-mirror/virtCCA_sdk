# virtCCA_sdk

## 介绍
The software development kit of virtCCA (virtualized ARM confidential computing architecture with trustzone), such as remote attestation, derived key based on hardware etc.

## 远程证明

### 编译

1. 安装依赖
    ```sh
    yum install tar cmake make git gcc gcc-c++ openssl-devel glib2-devel
    ```

2. 编译安装基线度量值计算工具
    ```sh
    cd attestation/rim_ref
    cmake -S . -B build
    cmake --build build
    cp output/gen_rim_ref /usr/local/bin
    ```
    **基线度量值计算工具gen_rim_ref会安装到/usr/local/bin目录下**

3. 编译安装远程证明sdk
    ```sh
    cd attestation/sdk
    cmake -S . -B build
    cmake --build build
    cmake --install build
    ```

    **远程证明用户态静态库libvccaattestation.a会安装到/usr/local/lib目录下，头文件attestation.h会安装到/usr/local/include目录下**

4. 编译安装`QCBOR 1.2`和`t_cose 1.1.2`依赖，编译远程证明样例代码和支持virtCCA的rats-tls需要使用:
    ```sh
    if [ ! -d "QCBOR" ]; then
        git clone https://github.com/laurencelundblade/QCBOR.git -b v1.2
    fi
    if [ ! -d "t_cose" ]; then
        git clone https://github.com/laurencelundblade/t_cose.git -b v1.1.2
    fi
    cd QCBOR
    make
    make install
    cd ../t_cose
    cmake -S . -B build
    cmake --build build
    cmake --install build
    ```

5. 编译远程证明样例代码，样例代码需要依赖远程证明sdk、`QCBOR 1.2`和`t_cose 1.1.2`，需要提前安装好

    **样例代码server端包含了调用远程证明sdk获取远程证明报告的代码，client端包含了报告解析和验证的代码，server和client使用TCP进行数据传递，代码仅供参考，建议使用rats-tls**

    ```sh
    cd attestation/samples
    cmake -S . -B build
    cmake --build build
    ```
    **远程证明样例代码的server和client会生成到build目录下**

6. 编译安装`libcbor`依赖，编译支持virtCCA的rats-tls需要使用:
    ```sh
    git clone https://github.com/PJK/libcbor.git
    cd libcbor
    cmake -S . -B build
    cd build
    make
    make install
    ```

7. 编译支持virtCCA的rats-tls，rats-tls需要依赖远程证明sdk、`libcbor`、`QCBOR 1.2`和`t_cose 1.1.2`，需要提前安装好
    ```sh
    cd attestation/rats-tls
    git clone https://github.com/inclavare-containers/rats-tls.git
    cd rats-tls
    git reset --hard 40f7b78403d75d13b1a372c769b2600f62b02692
    git apply ../*.patch
    bash build.sh -s -r
    ```

    **编译完成后会在bin目录下生成rats-tls.tar.gz软件包**

8. 编译启动时证明使用的initramfs，initramfs需要依赖支持virtCCA的rats-tls，需要提前编译好
    ```sh
    cd attestation/initramfs
    bash build.sh
    ```

### 使用说明

#### 远程证明样例代码

1. 启动server，server参数说明请使用`server -h`查看
    ```sh
    ./server
    ```

2. 启动client, 可以使用-m参数传递机密虚机的基线度量值用于校验，基线度量值可以使用基线度量值计算工具计算得到，client参数说明请使用`client -h`查看
    ```sh
    ./client -m 38d644db0aeddedbf9e11a50dd56fb2d0c663f664d63ad62762490da41562108
    ```


#### 支持virtCCA的rats-tls
1. 将rats-tls编译生产的rats-tls.tar.gz软件包拷贝到需要使用的机器，然后执行解压命令：
    ```sh
    tar -zxf rats-tls.tar.gz
    ```

2. 将rats-tls的动态库复制到/usr/lib目录下
    ```sh
    cp -r lib/rats-tls /usr/lib/
    ```

3. 导入环境变量后运行virtcca-server，virtcca-server参数说明请使用`virtcca-server -h`查看
    ```sh
    export LD_LIBRARY_PATH=/usr/lib/rats-tls:$LD_LIBRARY_PATH
    ./virtcca-server
    ```

3. 导入环境变量后运行virtcca-client，virtcca-client参数说明请使用`virtcca-client -h`查看
    ```sh
    export LD_LIBRARY_PATH=/usr/lib/rats-tls:$LD_LIBRARY_PATH
    ./virtcca-client
    ```
