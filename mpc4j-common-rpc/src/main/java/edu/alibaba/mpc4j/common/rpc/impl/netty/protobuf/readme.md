# 背景介绍

## ProtoBuf是什么

ProtoBuf是一套类似JSON和XML的数据传输格式和规范，用于不同应用或进程之间进行通信时使用。通信时，所传递的信息通过ProtoBuf定义的数据结构打包，然后编译成二进制的码流再进行传输或者存储。

ProtoBuf具有如下优点：

- 足够简单。
- 序列化后体积很小：消息大小只需要XML的1/10至1/3。
- 解析速度快：解析速度比XML快20至100倍。
- 多语言支持：支持C++、C#、Dart、Go、Java、Python、Rust等。定义好`proto`文件后，使用IDL编译器编译成所需的语言。
- 更好的兼容性：ProtoBuf设计的一个原则就是要能够很好的支持向下或向上兼容。

`mpc4j`的网络通信使用Netty实现，而Netty也提供了对Protobuf的支持。`mpc4j`使用ProtoBuf实现数据包的打包和解包操作。

# `proto`文件描述

ProtoBuf使用`proto`文件描述数据打包的方式。`proto`文件有自己的一套语法，很容易掌握。我们使用的`proto`文件如下所示。

```protobuf
// 定义proto文件符合proto3语法。
syntax = "proto3";
// 用该proto文件生成的Java文件的包路径。
option java_package = "edu.alibaba.mpc4j.common.rpc.impl.netty.protobuf";
// 用该proto文件生成的Java文件的文件名。
option java_outer_classname = "NettyRpcProtobuf";

message DataPacketProto {
  // 协议由两部分组成：head、payload，分别由HeaderProto和PayloadProto定义。
  HeaderProto headerProto = 1;
  PayloadProto payloadProto = 2;

  // 定义head
  message HeaderProto {
    // 任务ID
    int64 taskId = 1;
    // 协议ID
    int32 ptoId = 2;
    // 步骤ID
    int32 stepId = 3;
    // 补充信息
    int64 extraInfo = 4;
    // 发送方ID
    int32 senderId = 5;
    // 接收方ID
    int32 receiverId = 6;
  }

  // 定义payload
  message PayloadProto {
    // repeated表示可以存在多个（类似数组）
    repeated bytes payloadBytes = 1;
  }
}
```

# 将`proto`文件编译成Java文件

在MAC下执行下述代码，安装`protoc`工具：

```shell
brew install protobuf
```

安装完毕后，找到`proto`文件所在目录，执行下述命令：

```
protoc DataPacket.proto --java_out=.
```

即可在目录下生成`proto`对应的`Java`文件。

# 参考资料

1. 《一起学Netty（十）之 Netty使用Google的ProtoBuf》（https://blog.csdn.net/linuu/article/details/51360609）
2. 《Protobuf 数据类型对应》（https://blog.csdn.net/chuhui1765/article/details/100670318）