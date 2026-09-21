---
title: "TFE-GNN: A Temporal Fusion Encoder Using Graph Neural Networks for Fine-grained Encrypted Traffic Classification"
venue: "The Web Conference (WWW) 2023"
doi: "10.1145/3543507.3583227"
source_pdf: "WWW'23-TFE-GNN: A Temporal Fusion Encoder Using Graph Neural Networks for Fine-grained Encrypted Trafic Classification(1).pdf"
conversion: "Text-first Markdown extracted from PDF; consult the source PDF for exact figure and equation rendering."
---

# TFE-GNN: A Temporal Fusion Encoder Using Graph Neural Networks for Fine-grained Encrypted Traffic Classification
Haozhen Zhang Le Yu Xi Xiao<sup>∗</sup> Shenzhen International Graduate Department of Computing, The Hong Shenzhen International Graduate School, Tsinghua University Kong Polytechnic University School, Tsinghua University China Hong Kong, China China zhang-hz21@mails.tsinghua.edu.cn yulele08@gmail.com xiaox@sz.tsinghua.edu.cn Qing Li<sup>∗</sup> Francesco Mercaldo Xiapu Luo Peng Cheng Laboratory University of Molise Department of Computing, The Hong China IIT-CNR Kong Polytechnic University liq@pcl.ac.cn Italy Hong Kong, China francesco.mercaldo@unimol.it csxluo@comp.polyu.edu.hk

Qixu Liu
Institute of Information Engineering, Chinese Academy of Sciences

China liuqixu@iie.ac.cn

## ABSTRACT
Encrypted traffic classification is receiving widespread attention from researchers and industrial companies. However, the existing methods only extract flow-level features, failing to handle short flows because of unreliable statistical properties, or treat the header and payload equally, failing to mine the potential correlation between bytes. Therefore, in this paper, we propose a byte-level traffic graph construction approach based on point-wise mutual information (PMI), and a model named **T** emporal **F** usion **E** ncoder using **G** raph **N** eural **N** etworks ( **TFE-GNN** ) for feature extraction. In particular, we design a dual embedding layer, a GNN-based traffic graph encoder as well as a cross-gated feature fusion mechanism, which can first embed the header and payload bytes separately and then fuses them together to obtain a stronger feature representation. The experimental results on two real datasets demonstrate that TFE-GNN outperforms multiple state-of-the-art methods in fine-grained encrypted traffic classification tasks.

## CCS CONCEPTS
- **Security and privacy** → **Network security**; • **Information**

- **systems** → **Data mining**.

## KEYWORDS
Traffic Classification, User Behaviour, Graph Neural Networks

> ∗Corresponding authors.

This work is licensed under a Creative Commons Attribution International 4.0 License.

_WWW ’23, April 30–May 04, 2023, Austin, TX, USA_ © 2023 Copyright held by the owner/author(s). ACM ISBN 978-1-4503-9416-1/23/04. https://doi.org/10.1145/3543507.3583227

**ACM Reference Format:**

Haozhen Zhang, Le Yu, Xi Xiao, Qing Li, Francesco Mercaldo, Xiapu Luo, and Qixu Liu. 2023. TFE-GNN: A Temporal Fusion Encoder Using Graph Neural Networks for Fine-grained Encrypted Traffic Classification. In _Proceedings of the ACM Web Conference 2023 (WWW ’23), April 30–May 04, 2023, Austin, TX, USA._ ACM, New York, NY, USA, 10 pages. https://doi.org/10.1145/3543507.3583227

## 1 INTRODUCTION
To protect user privacy and anonymity, various encryption techniques are used to encrypt the transmission of network traffic [28]. Although Internet security is improved for a regular user, encryption technologies also provide a convenient disguise for some malicious attackers. Moreover, some privacy-enhanced tools like VPN and Tor [26] may be utilized to achieve illegal network transactions, such as weapon trading and drug sales, where it is difficult to trace the traffic source [13]. Traditional data packet inspection (DPI) methods concentrate on mining the potential patterns or keywords in data packets, which is time-consuming and loses its accuracy when facing encrypted traffic [24]. Consequently, how to effectively represent encrypted network traffic for more accurate detection and identification is a significant challenge.

To solve the above problems, many approaches have been proposed. The earliest port-based works are no longer effective due to the application of dynamic ports. Subsequently, a series of statistic-based methods emerged [8, 31, 37, 40, 43], which rely on statistical features from traffic flows (e.g., mean of packet length). Then, a machine learning classifier (e.g., random forest) is adopted to get the final prediction results. Unfortunately, these methods need hand-crafted feature engineering and may fail due to the unreliable/unstable flow-level statistical information in some cases [36]. Most statistical features of relatively short flows have higher deviations compared with long flows. For example, the flow length

generally obeys the long-tailed distribution [45], implying the universal existence of unreliable statistical features. Therefore, we use packet bytes instead of those statistical features.

Recently, graph neural networks (GNNs) [14] have been widely used in lots of applications of processing unstructured data. Due to the powerful expressiveness, GNNs can recognize specific topological patterns implied in graphs so that we can classify each graph with a predicted label. For the traffic classification task, most current GNN-based methods [1, 11, 21, 25, 29] construct graphs according to the correlation between packets, which actually is another usage form of statistical features and also suffers from the issue mentioned above. While the others do utilize packet bytes but have two major flaws: **1) Mix usage of the header and payload.** Existing methods simply treat the header and payload of a packet equally but ignore the difference in meaning between them. **2) Inadequate utilization of raw bytes.** Although the packet bytes are utilized, most methods regard packets as nodes and just take their raw bytes as node features, which does not make the most of them [11].

Based on the above observations, in this paper, we propose a byte-level traffic graph construction approach based on point-wise mutual information (PMI) and a novel model named **T** emporal **F** usion **E** ncoder using **G** raph **N** eural **N** etworks ( **TFE-GNN** ) for encrypted traffic classification. The byte-level traffic graphs are constructed by mining the correlation between bytes and served as inputs for TFE-GNN. TFE-GNN consists of three major submodules (i.e., dual embedding, traffic graph encoder, and cross-gated feature fusion mechanism). The dual embedding treats the header and payload of a packet separately and embeds them using two independent embedding layers. As for the traffic graph encoder which consists of multilayer GNNs, it encodes each graph into a high-dimensional graph vector. Finally, we use the cross-gated feature fusion mechanism to integrate header graph vectors and payload graph vectors, obtaining an overall representation vector of a packet. For end-to-end training, we employ a time series model to get final prediction results for downstream tasks. In the experiment section, we adopt a self-collected WWT dataset (including the data from WeChat, WhatsApp and Telegram) as well as the public ISCX dataset to compare TFE-GNN with more than a dozen baselines. The experimental results show that TFE-GNN surpasses almost all the baselines and comprehensively achieves the most excellent performance on the adopted datasets (e.g., 10.82% ↑ on the Telegram dataset, 4.58% ↑ on the ISCX-Tor dataset).

In summary, the main contributions of this paper include:

- We _first_ construct the byte-level traffic graph by converting a sequence of packet bytes into a graph, supporting traffic classification from a different perspective.

- We propose TFE-GNN, which treats the packet header and payload separately and encodes each byte-level traffic graph into an overall representation vector for each packet. Thus, TFE-GNN utilizes a packet-level representation vector rather than a flow-level one.

- To evaluate the performance of the proposed TFE-GNN, we compare it with several existing methods on the self-collected WWT dataset and public ISCX dataset [5, 15]. The result shows that, for user behaviour classification, TFE-GNN outperforms these methods in effectiveness.

## 2 PRELIMINARIES
### 2.1 Notations
In this paper, a graph is denoted by G = {V _,_ E _,_ X}, where V is the node set, E is the edge set, and X ∈ R<sup>|V|×</sup><sup>_��_</sup> is the initial feature matrix of nodes whereby the initial feature of node _�_ can be represented by _��_. We use A ∈{0 _,_ 1}<sup>|V|×|V|</sup> to represent the adjacency matrix of G, which satisfies that the entry ( _�, �_ ) of A, i.e., _�� �_, equals 1 if there is an edge between nodes _�_ and _�_, otherwise it is 0. We use _�_ ( _�_ ) to represent the neighborhood of node _�_. Moreover, we use _��_ to represent the embedding dimension in the _�_ -th layer.

For brevity and convenience, we extend the concept of traffic flows by introducing time-induced **Traffic Segments (TS)**, which are collectively referred to as traffic samples in the rest of the paper.

where _���_ denotes a single packet with its time stamp _��_, _�_ is the sequence length of a traffic segment, _�_ 1 _, ��_ are the start and end times of a traffic segment, respectively. From the definition above, the traffic segment has a broader scope than the traffic flow, i.e., each traffic flow can be seen as a traffic segment, but the reverse does not necessarily hold. In this way, we can directly take traffic segments as training samples and do inference using either traffic flows or traffic segments, which helps to improve flexibility and unleash the expressiveness of an end-to-end model.

### 2.2 Encrypted Traffic Classification
The encrypted traffic classification task aims to differentiate the traffic generated from various sources (e.g., applications, web pages or services) by using the information of traffic packets captured by professional software or programs. In this paper, we concentrate on in-app user behaviour classification which differentiates fine-grained user actions such as sending texts and sending pictures.

Assume that there are _�_ training samples and _�_ categories in total, let the _�_ -th traffic sample be a sequence _��_ = [ _��_ 1 _�, ��_ 2 _�_<sup>_,_</sup> · · · _, ����_ ], where _�_ is the sequence length and _��_<sup>_�_</sup> _�_ is the _�_ -th byte sequence of the _�_ -th traffic sample denoted by _��_<sup>_�_</sup> _�_ = [ _���_ 1 _, ���_ 2 _,_ · · · _,����_ ] where _�_ is the byte sequence length and _��� �_ denotes the _�_ -th byte value in the _�_ -th byte sequence of the _�_ -th traffic sample. According to the definition above, the (segment-level) encrypted classification task can be described formally as predicting the category _��_ of an unseen test sample _��_ with a designed and well-trained end-to-end model _�_ ( _��_ ) on _�_ training samples, where _��_ = 0 _,_ 1 _,_ · · · _, �_ − 1.

### 2.3 Message Passing Graph Neural Networks
Graph Neural Networks (GNNs) [14] are powerful models for handling unstructured data. With the application of the message passing paradigm (MP) [6] to GNNs (MP-GNNs), the node embedding vectors can be updated iteratively by integrating nodes’ embedding vectors in neighborhood through a specific aggregation strategy. Generally, the _�_ -th layer MP-GNNs can be formalized as two procedures (i.e., the message computation and aggregation):

where h _�_<sup>(</sup><sup>_�_)</sup> _,_ h _�_<sup>(</sup><sup>_�_)</sup> ∈ R<sup>_��_</sup> are the embedding vectors of nodes _�_ and ( _�_ ) _�_ in layer _�_. m _�_ is the computed message from node _�_ in layer _�_. MSG<sup>(</sup><sup>_�_)</sup> (·) is a message computation function parameterized by _��_<sup>_�_</sup> and AGG<sup>(</sup><sup>_�_)</sup> (·) is a message aggregation function parameterized by _��_<sup>_�_</sup> in layer _�_. Notably, _��_<sup>_�_</sup> is optional and the inputs of MP-GNNs are given by initial node feature vectors (i.e., h _�_<sup>(0)</sup> = x _�_ ).

Due to the high scalability of our proposed model, various GNN architectures can be easily adapted. Section 3.3 discusses the concrete choice of message aggregation strategies and our designed GNN architecture according to the design space of GNNs [42].

## 3 METHODOLOGY
### 3.1 Byte-level Traffic Graph Construction
We attempt to convert a sequence of bytes into a graph G = {V _,_ E _,_ X} by mining the potential correlation between bytes, where each element in V denotes a byte (i.e., a byte corresponds to a node in G). Note that all the bytes with the identical value share the same nodes so that there are no more than 256 nodes in G, which ensures a relatively small scale of traffic graphs.

**Correlation representation between bytes.** For edges, we can easily connect all bytes chronologically, which means creating an edge from byte _�_ to _�_ if byte _�_ comes before byte _�_ in a byte sequence. But we do not adopt this method since it will lead to a very dense graph and the topological structure will lack distinguishability. Therefore, inspired by [22] which uses cosine similarity to measure the correlation between two bytes, we adopt point-wise mutual information (PMI) [41], which is a prevalent measure for word association computation in natural language processing (NLP), to model the correlation between two bytes. In this paper, we represent the PMI value of bytes _�_ and _�_ as PMI( _�, �_ ).

**Edge creation.** The PMI value makes a comprehensive measurement of two co-occurrence bytes from the perspective of semantic associativity of bytes. We utilize it to create an edge between two bytes. A positive PMI value implies a high semantic correlation of bytes while a zero or a negative one implies little or no semantic correlation of bytes. Consequently, we only create an edge between two bytes whose PMI value is positive.

**Graph construction.** Below, we give the formal description of edges through the entries of adjacency matrix A of nodes _�_ and _�_:

The initial features of each node in graph G are given by the corresponding byte value, which ranges from 0 to 255. Notably, since PMI( _�, �_ ) = PMI( _�, �_ ), the byte-level traffic graphs are undirected.

### 3.2 Dual Embedding
The byte value is commonly utilized to serve as initial features for further vector embedding. Two bytes with different values correspond to two distinct embedding vectors. However, the meaning of a byte varies not only with the byte value itself, but also with the part of the byte sequence in which it is located. In other words, the representation meaning of two bytes with the identical value within the header and payload of a packet respectively may be completely different. The reason is that the payload carries the transmission contents of a packet while the header is the first part of a packet

that describes its contents. If we make two bytes with the identical value in the header and payload correspond to a same embedding vector, it is difficult for a model to converge to the optimum on these embedding parameters because of the obfuscated meaning.

For the rationale mentioned above, we treat the header and payload of a packet separately and construct byte-level traffic graphs for the two parts, respectively (i.e., byte-level traffic header graphs and byte-level traffic payload graphs). We adopt dual embedding with two embedding layers that do not share parameters to embed initial byte value features into high-dimensional embedding vectors for the two kinds of graphs, respectively.

**Dual embedding layer.** Assume that _�_ 0 denotes the embedding dimension and _�_ is the number of embedding elements (i.e., byte value). The dual embedding matrices, which consist of two embedding matrices, can be viewed as _�ℎ�����_ ∈ R<sup>_�_×</sup><sup>_�_0</sup> and _��������_ ∈ R<sup>_�_×</sup><sup>_�_0</sup>, where each row-wise entry represents the embedding vector of each byte value.

### 3.3 Traffic Graph Encoder with Cross-gated Feature Fusion
Since we construct byte-level traffic graphs based on the header and payload of packets, respectively, the following modules of TFE-GNN in this section are also dual, do not share parameters (architecture is the same) and can process in parallel.

**Traffic graph encoder.** To encode each traffic graph into a graph feature vector, we elaborately design a traffic graph encoder using stacked GraphSAGE [7], which is a powerful graph neural network. For every node _�_ in graph G, GraphSAGE computes the message from each neighboring node _�_ ∈ _�_ ( _�_ ) by normalizing its embedding vector using the degree of node _�_. Then, GraphSAGE computes the overall message of all neighboring nodes _�_ ( _�_ ) through element-wise mean operation and aggregates the overall message as well as the embedding vector of node _�_ through concatenation operation. Finally, a nonlinear transformation is applied to the embedding vector of node _�_, fnishing the forward procedure of one GraphSAGE layer. Formally, the message computation and aggregation of GraphSAGE can be described by:

where | _�_ ( _�_ )| is the neighbor number of node _�_, w<sup>(</sup><sup>_�_)</sup> ∈ R<sup>_��_−1×</sup><sup>_��_</sup> is the parameter in layer _�_, CONCAT(·) denotes the concatenation operation and _�_ (·) denotes the activation function. Specially, we employ parametric ReLU (PReLU) [9] as an activation function. PReLU scales each negative element value by a factor, which not only plays the effect of nonlinear transformation but also plays a role similar to that of the attention mechanism by different scale factors for each channel in the negative axis. Lastly, we normalize the updated feature vector h _�_<sup>(</sup><sup>_�_)</sup> by batch normalization (BN) [12].

Due to the over-smoothing issue [2] in the deep GNN model, we only stack GraphSAGE up to 4 layers and concatenate the output

<!-- Start of picture text -->
Traffic Flow<br>#1 Header & Payload............ #m Header & Payload............ #k Header & Payload........................<br>Byte Node<br>Sliding GraphSAGEPReLU Graph VectorHeader  ⊙ Packet #1 Graph Vector<br>45 00 02 4f... 0d 0a N × READOUT<br>BatchNorm Concat Packet #m Graph Vector<br>Sigmoid<br>JKN-like Concat Linear Linear Packet #k Graph Vector<br>Byte Node PReLU PReLU...<br>Sliding GraphSAGE Linear Linear<br>PReLU Sigmoid Downstream Models<br>60 02 45 0a... 12 44 N × BatchNorm READOUT<br>Payload<br>Graph Vector<br>JKN-like Concat LSTM GRU... Transformer<br>⊙<br>Byte-level Traffic Graph  Dual  Traffic Graph  Cross-gated  Temporal Information<br>Construction Embedding Encoder Feature Fusion Extraction<br>Header.........<br>Header Byte  Embedding...<br>45 00 02 4f... 0a 0d 0a......<br>Paloady<br>Payload Byte  Embedding<br>60 02 45 0a 0d 6f... 0a 5d 12 44<br><!-- End of picture text -->

**Figure 1: TFE-GNN Model Architecture**

feature vectors of each layer for each node _�_ to alleviate this problem, which is similar to Jumping Knowledge Network (JKN) [39]:

where h<sup>final</sup> _�_ is the final feature vector of node _�_. Finally, we apply mean pooling on all nodes to get a graph feature vector g:

where ⊕ denotes element-wise addition. For simplicity, we use g _ℎ_ and g _�_ to represent graph feature vectors extracted from traffic header graphs and traffic payload graphs, respectively.

**Cross-gated feature fusion.** Since we extract features from traffic header graphs and traffic payload graphs respectively mentioned in Section 3.2, we aim to create a reasonable relationship between g _ℎ_ and g _�_ to get an overall representation of packet bytes. To this end, we carefully design a feature fusion mechanism named cross-gated feature fusion, to fuse g _ℎ_ and g _�_ into a final encoded feature vector for each packet.

As shown in Figure 1, we adopt two filters, each of which consists of two linear layers with a PReLU activation function between them. First the two filters, which do not share parameters, are applied to g _ℎ_ and g _�_, respectively and then an element-wise sigmoid function is used to scale each element to [0 _,_ 1]. We consider the scaled vectors as gated vectors (s _ℎ_ and s _�_ for the header and the payload) and use them to crosswise filter the corresponding g _ℎ_ and g _�_. Such a mechanism allows the model to filter out unimportant information and reserve the significant one for the two feature vectors. As the first part of the packet, the header describes its important features. Thus, it is reasonable to use header gated vector s _ℎ_ to filter payload graph feature vector g _�_ and conversely use payload gated vector s _�_ to filter header graph feature vector g _ℎ_.

The cross-gated feature fusion can be formally represented by:

where w _ℎ_ 1 _,_ w _ℎ_ 2 _,_ w _�_ 1 _,_ w _�_ 2 ∈ R<sup>_��_×</sup><sup>_��_</sup> and b _ℎ_ 1 _,_ b _ℎ_ 2 _,_ b _�_ 1 _,_ b _�_ 2 ∈ R<sup>_��_</sup> are the weights and biases of linear layers. The symbol ⊙ denotes element-wise product and z is the overall representation vector of the packet bytes, which can be used for the downstream tasks.

### 3.4 End-to-End Training on Downstream Tasks
Based on the overall representation vector z for each packet, a packet-level or a segment-level classification task can be easily solved using a downstream classifier. We primarily focus on the segment-level task in this paper.

**Temporal information extraction.** Since we have already encoded raw bytes of each packet in a traffic segment into a representation vector z, the segment-level classification task can be considered as a time series prediction task. Here, we just adopt long short-term memory (LSTM) [10], which is a classical and famous time series model, as our baseline downstream model. LSTM is bidirectional with two layers and its output vectors are fed into a two-layer linear classifier with PReLU as its activation function to get the final prediction results. Seeing that we need to compute the difference between prediction results and the ground truth, we just adopt the cross entropy function as the loss function:

L _� ��_ − _�� �_ = CE(Classifer(LSTM(z1 _,_ z2 _,_ · · · _,_ z _�_ )) _,�_ ) (10) where _�_ is the segment length, _�_ is the ground truth and CE(·) denotes the cross entropy function.

Specially, we also attempt to employ a transformer layer [33] as a downstream model, which is also an effective time series model based on the self-attention mechanism. The experimental results for transformers are also presented in the experiment section.

## 4 EXPERIMENTS
In this section, we first present experimental settings. Then, we conduct experiments on multiple datasets and baselines and analyze the results. We also conduct an ablation study to show the effectiveness of each component in TFE-GNN. For comprehensive analysis, we design some model variants to evaluate the scalability of TFE-GNN and compare several baselines w.r.t. their model complexity. Finally,

we analyse the model sensitivity of TFE-GNN. In detail, we conduct the experiments to answer the following questions: **RQ1**: How is the usefulness of each component (Section 4.3)? **RQ2**: Which GNN architecture performs best (Section 4.4)? **RQ3**: How is the complexity of the TFE-GNN model (Section 4.5)? **RQ4**: To what extent can changes in hyper-parameters afect the effectiveness of TFE-GNN (Section 4.6)?

### 4.1 Experimental Settings
_4.1.1 Dataset._ In order to comprehensively evaluate the effectiveness of TFE-GNN, we adopt multiple datasets, i.e., ISCX VPNnonVPN [5], ISCX Tor-nonTor [15], and self-collected WWT datasets.

ISCX VPN-nonVPN is a public traffic dataset which contains ISCX-VPN and ISCX-nonVPN datasets. The ISCX-VPN dataset is collected over virtual private networks (VPNs) which are used for accessing some blocked websites or services and difficult to be recognized due to the obfuscation technology. Conversely, the traffic in ISCX-nonVPN is regular and not collected over VPNs.

Similarly, ISCX Tor-nonTor is a public dataset and ISCX-Tor dataset is collected over the onion router (Tor) whose traffic can be difficult to trace. Besides, ISCX-nonTor is also regular and not collected over Tor. For comparison, we use the ISCX VPN-nonVPN and ISCX Tor-nonTor datasets with six and eight user behaviour categories, respectively. We use SplitCap to obtain bidirectional flows from public datasets. Specially, due to the scarcity of flows in the ISCX-Tor dataset, we increase the training samples by dividing each flow into 60-second non-overlapping blocks in our experiments [27]. Finally, we utilize stratifed sampling to sequentially partition the training and testing dataset into 9:1 for all datasets.

The WWT dataset includes fine-grained user behaviour traffic data from three social media apps (i.e., WhatsApp, WeChat and Telegram), which have twelve, nine and six user behaviour categories, respectively. Unlike the public ISCX dataset, we additionally record the start and end timestamps of each user behaviour sample for traffic segmentation.

_4.1.2 Pre-processing._ For each dataset, we define and filter out two kinds of "anomalous" samples: **(1) Empty flows or segments**: the traffic flows or segments where all packets have no payload. **(2) Overlong flows or segments**: the traffic flows or segments whose length (i.e., the number of packets) is larger than 10000. An empty flow or segment does not contain any payload, thus we can not construct the corresponding graph. In fact, such samples are generally used to establish connections between clients and servers, having little discriminating information that helps to classify. An overlong flow or segment contains too many packets and a large number of bad packets or retransmission packets may appear in it due to temporarily bad network environment or other potential reasons. In most cases, such samples introduce too much noise, so we also consider overlong flows or segments as anomalous samples and remove them. Additionally, as for each rest sample of datasets, we remove bad packets and retransmission packets within.

For each packet in a flow or segment, we first remove the ones without payload. Then we remove the Ethernet header, which only provides some irrelevant information for classification. The source and destination IP addresses, and the port numbers are all removed

for the purpose of eliminating interference with sensitive information deriving from these IP addresses and port numbers.

_4.1.3 Implementation Details and Baselines._ In the stage of traffic graph construction, we set the max packet number of one sample to 50. The max payload byte length and the max header byte length are set to 150 and 40, respectively. The PMI window size is set to 5 by default. In the stage of training, we set the max training epoch to 120. The initial learning rate is set to 1e-2 and we use the Adam optimizer with a learning rate scheduler, which gradually decays the learning rate from 1e-2 to 1e-4. The batch size is 512, the ratio of warmup is 0.1 and the dropout rate is 0.2. We implement all models with PyTorch and run each experiment 10 times independently to take average on a single NVIDIA RTX 3080 GPU.

To give a fair comparison, we use four metrics, i.e., Overall Accuracy (AC), Precision (PR), Recall (RC) and Macro F1-score (F1), to evaluate TFE-GNN with following state-of-the-art baselines, including **_Traditional Feature Engineering Based Methods_** (i.e., AppScanner [31], CUMUL [23], K-FP (K-Fingerprinting) [8], FlowPrint [32], GRAIN [43], FAAR [19], ETC-PS [40]), **_Deep Learning Based Methods_** (i.e., FS-Net [18], EDC [16], FFB [44], MVML [4], DF [30], ET-BERT [17]), and **_Graph Neural Network Based Methods_** (i.e., GraphDApp [29], ECD-GNN [11]).

### 4.2 Comparison Experiments
The comparison results on WWT and ISCX datasets are shown in Tables 1 and 2. According to Tables 1 and 2, we can draw the following conclusions: (1) TFE-GNN reaches the best performance compared with several baselines on the WWT dataset. Additionally, TFE-GNN also achieves the best results on four metrics, which further comprehensively demonstrates the effectiveness of our method. (2) Notably we can find that almost all the baselines perform poor on the Telegram dataset, it is due to the fact that the usage of VPNs increases the classification difficulty and introduces some background noise in case of provisionally bad network conditions caused by VPNs. However, TFE-GNN also has an outstanding result on the Telegram dataset (10.82% f1-score improvement over the second highest), which benefts from the powerful byte encoding capability of TFE-GNN. (3) Compared with the two GNN-based methods similar to ours, i.e., GraphDApp and ECD-GNN, TFE-GNN outperforms both in all aspects. As for GraphDApp, its scheme of traffic interaction graph construction limits the expressiveness of the model. Although graphs from different traffic flows are slightly distinct in the aspect of traffic bursts, the edges between different bursts are unreasonable, which hinders feature extraction. Furthermore, an earlier burst can not "interact" with the later one using shallow GNNs because of the long and continuous connections between bursts. However, ECD-GNN is very unstable on different datasets. The reason is that the constructed graphs are lack of graph topology specificity and have highly similar structures, which significantly decreases its performance stability. With our elaborated byte-level graph construction approach, TFE-GNN can encode raw bytes well and has greater distinguishability among different traffic categories. (4) The extensive experiments on public datasets, i.e., the ISCX VPN-nonVPN and the ISCX Tor-nonTor, show that TFEGNN can also perform well on more complicated datasets. From the Table 2, TFE-GNN is superior to almost all the baselines on public

**Table 1: Experimental Results on Self-collected WeChat, WhatsApp and Telegram Datasets**

|Dataset||We|Chat|||What|sApp|||Tele|gram||
|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Model|AC|PR|RC|F1|AC|PR|RC|F1|AC|PR|RC|F1|
|AppScanner [31]|0.9927|0.9908|0.9904|0.9905|0.9790|0.9688|0.9601|0.9628|0.8379|0.8154|0.8653|0.8304|
|K-FP [8]|0.9741|0.9665|0.9630|0.9645|0.9710|0.9589|0.9515|0.9526|0.8797|0.8378|0.8990|0.8567|
|FlowPrint [32]|0.7429|0.5302|0.6380|0.5532|0.6197|0.3820|0.4934|0.3880|0.4833|0.4025|0.5000|0.4311|
|CUMUL [23]|0.9472|0.9497|0.9412|0.9390|0.9855|0.9835|0.9699|0.9756|0.8330|0.7980|0.8471|0.8053|
|GRAIN [43]|0.9404|0.9366|0.9369|0.9251|0.9724|0.9685|0.9475|0.9550|0.8003|0.7615|0.7903|0.7407|
|FAAR [19]|0.9873|0.9863|0.9847|0.9854|0.9790|0.9683|0.9566|0.9597|0.8184|0.7884|0.8507|0.8018|
|ETC-PS [40]|0.9863|0.9864|0.9831|0.9846|0.9833|0.9743|0.9685|0.9703|0.8477|0.8295|0.8710|0.8382|
|FS-Net [18]|0.9223|0.9446|0.9196|0.8964|0.9942|0.9949|0.9919|0.9933|0.8469|0.8161|0.8744|0.8272|
|DF [30]|0.9800|0.9757|0.9751|0.9751|0.8978|0.7954|0.8406|0.8143|0.8251|0.8206|0.8542|0.7960|
|EDC [16]|0.9746|0.9653|0.9625|0.9620|0.9732|0.9589|0.9526|0.9546|0.8153|0.8118|0.8372|0.7896|
|FFB [44]|0.9675|0.9691|0.9661|0.9644|0.9350|0.8957|0.8767|0.8708|0.7990|0.7630|0.8169|0.7802|
|MVML [4]|0.9643|0.9519|0.9540|0.9526|0.9456|0.9302|0.9009|0.8971|0.7943|0.7413|0.7636|0.7340|
|ET-BERT [17]|0.9505|0.9368|0.9285|0.9266|0.9107|0.8934|0.8697|0.8439|0.7679|0.8712|0.7989|0.7858|
|GraphDApp [29]|0.8763|0.8368|0.8378|0.8330|0.8753|0.7615|0.8060|0.7791|0.7766|0.7575|0.7627|0.7227|
|ECD-GNN [11]|0.9863|0.9847|0.9830|0.9835|0.9811|0.9722|0.9647|0.9672|0.1810|0.0353|0.1641|0.0528|
|**TFE-GNN**|**0.9956**|**0.9953**|**0.9939**|**0.9946**|**0.9971**|**0.9957**|**0.9966**|**0.9961**|**0.9586**|**0.9584**|**0.9742**|**0.9649**|

**Table 2: Experimental Results on Public ISCX VPN-nonVPN and ISCX Tor-nonTor Datasets**

|Dataset||ISCX|-VPN|||ISCX-n|onVPN|||ISCX|-Tor|||ISCX-|nonTor||
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Model|AC|PR|RC|F1|AC|PR|RC|F1|AC|PR|RC|F1|AC|PR|RC|F1|
|AppScanner [31]|0.8889|0.8679|0.8815|0.8722|0.7576|0.7594|7465|0.7486|0.7543|0.6629|0.6042|0.6163|0.9153|0.8435|0.8140|0.8273|
|K-FP [8]|0.8713|0.8750|0.8748|0.8747|0.7551|0.7478|0.7354|0.7387|0.7771|0.7417|0.6209|0.6313|0.8741|0.8653|0.7792|0.8167|
|FlowPrint [32]|0.8538|0.7451|0.7917|0.7566|0.6944|0.7073|0.7310|0.7131|0.2400|0.0300|0.1250|0.0484|0.5243|0.7590|0.6074|0.6153|
|CUMUL [23]|0.7661|0.7531|0.7852|0.7644|0.6187|0.5941|0.5971|0.5897|0.6686|0.5349|0.4899|0.4997|0.8605|0.8143|0.7393|0.7627|
|GRAIN [43]|0.8129|0.8077|0.8109|0.8027|0.6667|0.6532|0.6664|0.6567|0.6914|0.5253|0.5346|0.5234|0.7895|0.6714|0.6615|0.6613|
|FAAR [19]|0.8363|0.8224|0.8404|0.8291|0.7374|0.7509|0.7121|0.7252|0.6971|0.5915|0.4876|0.4814|0.9103|0.8253|0.7755|0.7959|
|ETC-PS [40]|0.8889|0.8803|0.8937|0.8851|0.7273|0.7414|0.7133|0.7208|0.7486|0.6811|0.5929|0.6033|0.9365|0.8700|0.8311|0.8486|
|FS-Net [18]|0.9298|0.9263|0.9211|0.9234|0.7626|0.7685|0.7534|0.7555|0.8286|0.7487|0.7197|0.7242|0.9278|0.8368|0.8254|0.8285|
|DF [30]|0.8012|0.7799|0.8152|0.7921|0.6742|0.6857|0.6717|0.6701|0.6514|0.4803|0.4767|0.4719|0.8568|0.8003|0.7415|0.7590|
|EDC [16]|0.7836|0.7747|0.8108|0.7888|0.6970|0.7153|0.7000|0.6978|0.6400|0.4980|0.4528|0.4504|0.8692|0.7994|0.7411|0.7451|
|FFB [44]|0.8304|0.8714|0.8149|0.8335|0.7020|0.7274|0.6945|0.7050|0.6343|0.4870|0.5203|0.4952|0.8954|0.7545|0.7430|0.7430|
|MVML [4]|0.6491|0.7231|0.6198|0.6151|0.5126|0.5751|0.4707|0.4806|0.6343|0.3914|0.4104|0.3752|0.7235|0.5488|0.5512|0.5457|
|ET-BERT [17]|0.9532|0.9436|0.9507|0.9463|**0.9167**|0.9245|**0.9229**|0.9235|0.9543|0.9242|0.9606|0.9397|0.9029|0.8560|0.8217|0.8332|
|GraphDApp [29]|0.6491|0.5668|0.6103|0.5740|0.4495|0.4230|0.3647|0.3614|0.4286|0.2557|0.2509|0.2281|0.6936|0.5447|0.5398|0.5352|
|ECD-GNN [11]|0.1111|0.0185|0.1667|0.0333|0.0606|0.0101|0.1667|0.0190|0.0571|0.0071|0.1250|0.0135|0.9078|0.8015|0.8168|0.7977|
|**TFE-GNN**|**0.9591**|**0.9526**|**0.9593**|**0.9536**|0.9040|**0.9316**|0.9190|**0.9240**|**0.9886**|**0.9792**|**0.9939**|**0.9855**|**0.9390**|**0.8742**|**0.8335**|**0.8507**|

datasets except for the ISCX-nonVPN dataset, on which TFE-GNN and ET-BERT all reach similar results. However, ET-BERT is a large model with very complex model architecture while TFE-GNN is a slighter model which achieves the steadiest and best results on all datasets. We will analyse the model complexity in Section 4.5 later.

### 4.3 Ablation Study (RQ1)
In this section, we conduct an ablation study of TFE-GNN on the ISCX-VPN and the ISCX-Tor datasets and show experimental results in Table 3. To facilitate the presentation of results, we denote header, payload, dual embedding module, jumping knowledge network-like concatenation, cross-gated feature fusion and activation function and batch normalization as ’H’, ’P’, ’DUAL’, ’JKN’, ’CGFF’ and ’A&N’, respectively. Specially, we not only verify the effectiveness of each component in TFE-GNN, but also test the impact of some alternative modules or operations, including ’SUM’ and ’MAX’ operation on node features to get graph representation vectors instead of the

default ’MEAN’, and ’GRU’ or ’TRANSFORMER’ modules to serve as downstream models instead of LSTM.

From the component ablation study of Table 3, we can draw the following conclusions: (1) The packet headers play a more important role in classification than the packet payloads and different datasets have different levels of the header and payload importance (the f1-score decreases by 2.5% when switching the header to payload on the ISCX-VPN dataset and by 21.06% on the ISCX-Tor dataset). (2) The usage of dual embedding increases the f1-score by 3.63% and 0.95%, which indicates its general effectiveness. JKN-like concatenation and cross-gated feature fusion both enhance the performance of TFE-GNN by a similar margin on two datasets. (3) We further verify the impact of the activation function and batch normalization and a significant performance drop can be seen on both datasets, which demonstrates the necessity of this two operations.

While on the rest part of Table 3, we can also obtain the following several points: (1) The element-wise summation on node features performs worse than the mean operation by a margin of 11.1% and

**Table 3: Ablation Study of TFE-GNN on ISCX-VPN and ISCX-Tor Datasets**

|Method|H|P|DUAL|JKN|CGFF|A&N|AC|PR|RC|F1|
|---|---|---|---|---|---|---|---|---|---|---|
|w/o P|✓|×|×|✓|×|✓|0.8713 | 0.9874|0.8261 | 0.9788|0.8228 | 0.9934|0.8230 | 0.9806|
|w/o H|×|✓|×|✓|×|✓|0.8051 | 0.8726|0.8232 | 0.7780|0.7957 | 0.7809|0.7980 | 0.7700|
|w/o DUAL|✓|✓|×|✓|✓|✓|0.9310 | 0.9829|0.9149 | 0.9747|0.9209 | 0.9801|0.9173 | 0.9760|
|w/o JKN|✓|✓|✓|×|✓|✓|0.9474 | 0.9790|0.9365 | 0.9736|0.9397 | 0.9879|0.9374 | 0.9795|
|w/o CGFF|✓|✓|✓|✓|×|✓|0.9445 | 0.9800|0.9329 | 0.9717|0.9371 | 0.9847|0.9339 | 0.9770|
|w/o A&N|✓|✓|✓|✓|✓|×|0.6105 | 0.2212|0.5576 | 0.0555|0.5487 | 0.1180|0.5289 | 0.0548|
|w/ SUM|✓|✓|✓|✓|✓|✓|0.8497 | 0.8194|0.8549 | 0.7287|0.8380 | 0.6986|0.8426 | 0.6891|
|w/ MAX|✓|✓|✓|✓|✓|✓|0.8480 | 0.9870|0.8328 | 0.9752|0.8115 | 0.9778|0.8094 | 0.9751|
|w/ GRU|✓|✓|✓|✓|✓|✓|0.8550 | 0.8932|0.8489 | 0.8702|0.8287 | 0.8664|0.8294 | 0.8610|
|w/ TRANSFORMER|✓|✓|✓|✓|✓|✓|0.6754 | 0.9777|0.5706 | 0.9753|0.5992 | 0.9820|0.5658 | 0.9828|
|**TFE-GNN** **(default)**|✓|✓|✓|✓|✓|✓|**0.9591** **|** **0.9886**|**0.9526** **|** **0.9792**|**0.9593** **|** **0.9939**|**0.9536** **|** **0.9855**|

29.64%, respectively on two datasets w.r.t. f1-score. However, the element-wise maximum decreases the f1-score to worse results on the ISCX-VPN dataset while only decreases f1-score a little on the ISCX-Tor dataset. (2) We change the default downstream model LSTM to GRU, which worsens all metrics about ~10% on both datasets because of the simpler architecture of GRU. Furthermore, we employ a transformer as a downstream model for comprehensive experiments. The results show that transformer performs well on the ISCX-Tor dataset (drops f1-score within ~1%) while receives almost ~40% drop on the ISCX-VPN dataset.

### 4.4 GNN Architecture Variants Study (RQ2)
To illustrate the scalability of GNN-based temporal fusion encoder, we select some classical GNN architectures as variants (e.g., GAT [34], GIN [38], GCN [14] and SGC [35]) for comparison on Telegram, ISCX-VPN and ISCX-Tor datasets.

From Figure 2, we can find that GraphSAGE [7] achieves the best f1-score on three datasets. As for the rest variants, a noticeable drop in performance can be discovered, especially for GAT [34]. The rationale behind the results is that GNN models are easy to overft on small-scale graphs like ours (number of nodes is up to 256). As for GAT [34], the application of the attention mechanism in neighborhood feature aggregation exacerbates overftting, which leads to a significant decline in f1-score. Among the three datasets, the relatively small fuctuation of the results on the Telegram dataset further validates the analysis above, which benefts from its larger number of training samples.

<!-- Start of picture text -->
1.00 Telegram ISCX-VPN ISCX-Tor<br>0.95<br>0.90<br>0.85<br>0.80<br>0.75<br>0.70<br>GAT GCN GIN SGC GraphSAGE<br>GNN Architecture Variants<br>F1-Score<br><!-- End of picture text -->

**Figure 2: GNN Architecture Variants Study w.r.t. F1-score**

Also, a segment-level global feature can be added and shared with all nodes within one traffic graph using our model architecture if needed, which naturally takes local (packet) and global (segment)

context into account simultaneously. It can be easily realized by performing concatenation, element-wise addition or other similar operations due to the strong scalability of TFE-GNN.

### 4.5 Model Complexity Analysis (RQ3)
To comprehensively evaluate the trade-of between model performance and model complexity, we present the foating point operations (FLOPs) and the model size of all baselines except for the traditional models in Table 4.

From Tables 4 and 2, we can draw a conclusion that TFE-GNN achieves the most significant improvement on public datasets with relatively slight model complexity increasing. Although ET-BERT reaches comparable results on the ISCX-nonVPN dataset, the FLOPs of ET-BERT are approximately fve times as large as that of TFEGNN and the number of model parameters are also doubled, which generally indicates longer model inference time and requires more computation resources. Furthermore, the pre-training stage of ETBERT is very time-consuming and costs a lot due to the large amount of extra data during pre-training and the high model complexity. In comparison, TFE-GNN can achieve higher accuracy while reducing the training or inference costs.

**Table 4: Model FLOPs and Parameters**

|Model|FLOPs(M)|Parameters(M)|
|---|---|---|
|FS-Net[18]|1.0e+2|3.2e+0|
|DF[30]|2.8e+0|9.3e-1|
|EDC[16]|2.2e+1|2.2e+1|
|FFB[44]|2.6e+2|1.7e+0|
|MVML[4]|7.2e-4|3.7e-4|
|ET-BERT[17]|1.1e+4|8.6e+1|
|GraphDApp[29]|3.8e-2|1.1e-2|
|ECD-GNN[11]|2.9e+1|1.4e+0|
|**TFE-GNN**|2.2e+3|4.4e+1|

### 4.6 Model Sensitivity Analysis (RQ4)
**(1) The Impact of Dual Embedding Dimension**. To investigate the infuence of hidden dimension of the dual embedding layer, we conduct sensitivity experiments and show results in Figure 3a. As we can see, f1-score is increasing rapidly when embedding dimension is lower than 100. After that point, the model performance tends to be stable as the dimension changes. For reducing computation consuming, we just take embedding dimension 50 as our

default setting. **(2) The Impact of PMI Window Size**. From Figure 3b, we can find that a smaller window size usually results in better f1-score. The larger the window size, the more edges will be added in the traffic graphs, and the model will be harder to discriminate different traffic categories due to the too dense graphs. **(3) The Impact of Segment Length**. From Figure 3c, we can draw a conclusion that a short segment length for training usually makes the performance better. When the segment length becomes longer, more noise will be introduced and the downstream model LSTM has shortcomings in long sequence modeling, afecting the evaluation results. On the other hand, our method can achieve high accuracy when facing a short traffic flow or segment, reducing the amount of computation while improving performance.

<!-- Start of picture text -->
1.0 0.98 ISCX-VPN 1.00<br>0.9 0.96 ISCX-Tor 0.95<br>0.94<br>0.8 0.92 0.90<br>0.70.6 ISCX-VPNISCX-Tor 0.900.880.86 0.850.80 ISCX-VPNISCX-TOR<br>0.84<br>0 200 400 600 800 1000 0 5 10 15 20 25 30 0 20 40 60 80 100<br>Embedding Dimension PMI Window Size Segment Length<br>F1-Score F1-Score F1-Score<br><!-- End of picture text -->

**(a) Embedding Dim (b) PMI Window Size (c) Segment Length**

**Figure 3: Model Sensitivity Analysis w.r.t. Dual Embedding Dimension, PMI Window Size and Segment Length on ISCXVPN and ISCX-Tor Datasets (The shallow lines are attained by smoothing the dark plotted lines)**

## 5 RELATED WORK
**Traditional Feature Engineering Based Methods.** Various methods leverage statistical features to depict the packet property and employ traditional machine learning models to conduct classification. AppScanner uses bidirectional flow characteristics (i.e., outgoing and incoming) to extract features from traffic flows w.r.t. packet length and interval time [31]. CUMUL uses the features of cumulative packet length [23] and GRAIN [43] uses payload length as its features. ETC-PS utilizes the path signature theory to enhance the original packet length features [40], and Liu _et al_. exploited packet length sequences using wavelet decomposition [19]. Conti _et al_. [3] adopts hierarchical clustering for feature extraction. The fingerprinting matching is also used in the traffic classification task. FlowPrint [32] constructs correlation graphs as traffic fingerprinting by computing activity value between destinations IP. K-FP [8] creates fingerprinting using random forest and matches unseen samples by k-nearest neighbor. All of these methods suffer from the unreliable features (mentioned in Section 1).

**Deep Learning Based Methods.** With the popularity of deep learning models, many traffic classification approaches are developed based on them. EDC [16] uses some header information of packets (e.g., protocol types, packet length and time duration) to build features for multilayer perceptions (MLPs). MVML [4] designs local and global features using packet length and time delay sequences, and simply employs a fully-connected layer for classification. Furthermore, FS-Net [18], DF [30] as well as RBRN [47] all utilize traffic flow sequences like packet length sequences to serve as the inputs of deep learning models. Additionally, DF and RBRN use convolutional neural networks (CNNs) while FS-Net utilizes

gated recurrent units (GRUs) to extract temporal information of such sequences. For some other methods, packet bytes are used as model inputs to extract features. FFB [44] uses raw bytes and packet length sequences as features to feed into CNNs and RNNs. While Deep Packet [20] utilizes CNNs and autoencoders for feature extraction. Recently, pre-training models are utilized to pre-train on large-scale traffic data. To give an example, ET-BERT [17] designs two novel pre-training tasks for traffic classification, which enhance the representation ability of raw bytes but are very timeconsuming and costly. In a word, these methods can not obtain the discriminative information which is contained in raw bytes very well in a relatively efcient way, while our approach solves this pain and difficulty by introducing byte-level traffic graphs.

**Graph Neural Network Based Methods.** Graph neural networks have strong potential in processing unstructured data and can be migrated to many felds. For encrypted traffic classification, GraphDApp [29] constructs traffic interaction graphs using traffic bursts and employs graph isomorphism network [38] to learn representations. MAppGraph [25] constructs traffic graphs based on different flows and time slices within a traffic chunk, which is almost impossible to construct a complete graph in the face of a short traffic segment. GCN-ETA [46] is a malicious traffic detection method. To construct a graph, it will create an edge if two flows share common IP, which may result in a very dense graph. MEMG [1] utilizes markov chains to construct graphs from flows while GAP-WF [21] maps a flow as a node in graphs and connects edges between flows which share the same identity of the clients. Besides, Huoh _et al_. [11] directly created edges based on the chronological relationship of packets among a flow, being lack of specificity. These methods all construct graphs at the level of traffic flows, which are vulnerable if there is too much noise within flows.

## 6 CONCLUSION AND FUTURE WORK
We propose an approach to construct byte-level traffic graphs and a model named TFE-GNN for encrypted traffic classification. The byte-level traffic graph construction approach can mine the potential correlation between raw bytes and generate discriminative traffic graphs. TFE-GNN is designed to extract high-dimensional features from constructed traffic graphs. Finally, TFE-GNN can encode each packet into an overall representation vector, which can be used for some downstream tasks like traffic classification. Several baselines are selected to evaluate the effectiveness of TFE-GNN. The experimental results show that our proposed model comprehensively surpasses all the baselines on the WWT and the ISCX datasets. Elaborately designed experiments further demonstrate that TFE-GNN has strong effectiveness.

In the future, we will attempt to improve TFE-GNN in terms of the following limitations. **(1) Limited graph construction approach**. The graph topology of the proposed model is determined before the training procedure, which may result in non-optimal performance. Moreover, the TFE-GNN can not cope with the bytelevel noise implied in the raw bytes of each packet. **(2) Unused temporal information implied in byte sequences**. The bytelevel traffic graphs are constructed without introducing the explicit temporal characteristics of byte sequences.

## ACKNOWLEDGMENTS
This work was supported in part by the National Natural Science Foundation of China (61972219,62202406,61972189), the Research and Development Program of Shenzhen (JCYJ20190813174403598, SGDX20190918101201696), the Overseas Research Cooperation Fund of Tsinghua Shenzhen International Graduate School (HW2021013), Shenzhen Science and Technology Innovation Commission: Research Center for Computer Network (Shenzhen) Ministry of Education, HK ITF Project (GHP/052/19SZ), and the Key Laboratory of Network Assessment Technology, Institute of Information Engineering, Chinese Academy of Sciences, Beijing, China.

## REFERENCES
- [1] Wei Cai, Gaopeng Gou, Minghao Jiang, Chang Liu, Gang Xiong, and Zhen Li. 2021. MEMG: Mobile Encrypted Traffic Classification With Markov Chains and Graph Neural Network. In _IEEE International Conference on High Performance Computing and Communications_. 478–486.

- [2] Weilin Cong, Morteza Ramezani, and Mehrdad Mahdavi. 2021. On Provable Benefts of Depth in Training Graph Convolutional Networks. In _Conference on Neural Information Processing Systems_. 9936–9949.

- [3] Mauro Conti, Luigi Vincenzo Mancini, Riccardo Spolaor, and Nino Vincenzo Verde. 2015. Analyzing Android Encrypted Network Traffic to Identify User Actions. _IEEE Transactions on Information Forensics and Security_ 11, 1 (2015), 114–125.

- [4] Yanjie Fu, Junming Liu, Xiaolin Li, and Hui Xiong. 2018. A Multi-Label MultiView Learning Framework for In-App Service Usage Analysis. _ACM Transactions on Intelligent Systems and Technology_ 9, 4 (2018), 1–24.

- [5] Gerard Drapper Gil, Arash Habibi Lashkari, Mohammad Mamun, and Ali A. Ghorbani. 2016. Characterization of Encrypted and VPN Traffic Using TimeRelated Features. In _International Conference on Information Systems Security and Privacy_. 407–414.

- [6] Justin Gilmer, Samuel S. Schoenholz, Patrick F. Riley, Oriol Vinyals, and George E. Dahl. 2017. Neural Message Passing for Quantum Chemistry. In _International Conference on Machine Learning_. 1263–1272.

- [7] Will Hamilton, Zhitao Ying, and Jure Leskovec. 2017. Inductive Representation Learning on Large Graphs. In _Conference on Neural Information Processing Systems_.

- [8] Jamie Hayes and George Danezis. 2016. k-fingerprinting: a Robust Scalable Website Fingerprinting Technique. In _USENIX Security Symposium_. 1187–1203.

- [9] Kaiming He, Xiangyu Zhang, Shaoqing Ren, and Jian Sun. 2015. Delving Deep into Rectifers: Surpassing Human-Level Performance on ImageNet Classification. In _IEEE International Conference on Computer Vision_. 1026–1034.

- [10] Sepp Hochreiter and Jürgen Schmidhuber. 1997. Long Short-Term Memory. _Neural Computation_ 9, 8 (1997), 1735–1780.

- [11] Ting-Li Huoh, Yan Luo, and Tong Zhang. 2021. Encrypted Network Traffic Classification Using a Geometric Learning Model. In _IFIP/IEEE Symposium on Integrated Network Management_. 376–383.

- [12] Sergey Iofe and Christian Szegedy. 2015. Batch Normalization: Accelerating Deep Network Training by Reducing Internal Covariate Shift. In _International Conference on Machine Learning_. 448–456.

- [13] Julian Jang-Jaccard and Surya Nepal. 2014. A survey of emerging threats in cybersecurity. _J. Comput. System Sci._ 80, 5 (2014), 973–993.

- [14] Thomas N. Kipf and Max Welling. 2017. Semi-Supervised Classification with Graph Convolutional Networks. In _International Conference on Learning Representations_.

- [15] Arash Habibi Lashkari, Gerard Draper-Gil, Mohammad Saiful Islam Mamun, and Ali A. Ghorbani. 2017. Characterization of Tor Traffic Using Time Based Features. In _International Conference on Information System Security and Privacy_. 253–262.

- [16] Wenbin Li and Gaspard Quenard. 2021. Towards a Multi-Label Dataset of Internet Traffic for Digital Behavior Classification. In _International Conference on Computer Communication and the Internet_. 38–46.

- [17] Xinjie Lin, Gang Xiong, Gaopeng Gou, Zhen Li, Junzheng Shi, and Jing Yu. 2022. ET-BERT: A Contextualized Datagram Representation with Pre-training Transformers for Encrypted Traffic Classification. In _The Web Conference_. 633– 642.

- [18] Chang Liu, Longtao He, Gang Xiong, Zigang Cao, and Zhen Li. 2019. FS-Net: A Flow Sequence Network For Encrypted Traffic Classification. In _IEEE Conference on Computer Communications_. 1171–1179.

- [19] Xue Liu, Shigeng Zhang, Huihui Li, and Weiping Wang. 2021. Fast Application Activity Recognition with Encrypted Traffic. In _International Conference on Wireless Algorithms, Systems, and Applications_. 314–325.

- [20] Mohammad Lotfollahi, Mahdi Jafari Siavoshani, Ramin Shirali Hossein Zade, and Mohammdsadegh Saberian. 2020. Deep packet: a novel approach for encrypted traffic classification using deep learning. _Soft Computing_ 24, 3 (2020), 1999–2012.

- [21] Jie Lu, Gaopeng Gou, Majing Su, Dong Song, Chang Liu, Chen Yang, and Yangyang Guan. 2021. GAP-WF: Graph Attention Pooling Network for Finegrained SSL/TLS Website Fingerprinting. In _IEEE International Joint Conference on Neural Network_. 1–8.

- [22] Kelong Mao, Xi Xiao, Guangwu Hu, Xiapu Luo, Bin Zhang, and Shutao Xia. 2021. Byte-Label Joint Attention Learning for Packet-grained Network Traffic Classification. In _International Workshop on Quality of Service_. 1–10.

- [23] Andriy Panchenko, Fabian Lanze, Andreas Zinnen, Martin Henze, Jan Pennekamp, Klaus Wehrle, and Thomas Engel. 2016. Website Fingerprinting at Internet Scale. In _Annual Network and Distributed System Security Symposium_.

- [24] Eva Papadogiannaki and Sotiris Ioannidis. 2021. A Survey on Encrypted Network Traffic Analysis Applications, Techniques, and Countermeasures. _Comput. Surveys_ 54, 6 (2021), 1–35.

- [25] Thai-Dien Pham, Thien-Lac Ho, Tram Truong-Huu, Tien-Dung Cao, and HongLinh Truong. 2021. MAppGraph: Mobile-App Classification on Encrypted Network Traffic using Deep Graph Convolution Neural Networks. In _Annual Computer Security Applications Conference_. 1025–1038.

- [26] E Ramadhani. 2018. Anonymity communication VPN and Tor: a comparative study. _Journal of Physics: Conference Series_ 983, 1 (2018), 012060.

- [27] Tal Shapira and Yuval Shavitt. 2021. FlowPic: A Generic Representation for Encrypted Traffic Classification and Applications Identifcation. _IEEE Transactions on Network and Service Management_ 18, 2 (2021), 1218–1232.

- [28] Ritik Sharma, Sarishma Dangi, and Preeti Mishra. 2021. A Comprehensive Review on Encryption based Open Source Cyber Security Tools. In _IEEE International Conference on Signal Processing, Computing and Control_. 614–619.

- [29] Meng Shen, Jinpeng Zhang, Liehuang Zhu, Ke Xu, and Xiaojiang Du. 2021. Accurate Decentralized Application Identifcation via Encrypted Traffic Analysis Using Graph Neural Networks. _IEEE Transactions on Information Forensics and Security_ 16, 1 (2021), 2367–2380.

- [30] Payap Sirinam, Mohsen Imani, Marc Juarez, and Matthew K Wright. 2018. Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning. In _Conference on Computer and Communications Security_. 1928–1943.

- [31] Vincent F. Taylor, Riccardo Spolaor, Mauro Conti, and Ivan Martinovic. 2016. AppScanner: Automatic Fingerprinting of Smartphone Apps From Encrypted Network Traffic. In _IEEE European Symposium on Security and Privacy_. 439–454.

- [32] Thijs van Ede, Riccardo Bortolameotti, Andrea Continella, Jingjing Ren, Daniel J. Dubois, and Martina Lindorfer. 2020. FlowPrint: Semi-Supervised Mobile-App Fingerprinting on Encrypted Network Traffic. In _Annual Network and Distributed System Security Symposium_.

- [33] Ashish Vaswani, Noam Shazeer, Niki Parmar, Jakob Uszkoreit, Llion Jones, Aidan N Gomez, Łukasz Kaiser, and Illia Polosukhin. 2017. Attention is All you Need. In _Conference on Neural Information Processing Systems_.

- [34] Petar Veličković, Guillem Cucurull, Arantxa Casanova, Adriana Romero, Pietro Liò, and Yoshua Bengio. 2018. Graph Attention Networks. In _International Conference on Learning Representations_.

- [35] Felix Wu, Amauri Souza, Tianyi Zhang, Christopher Fifty, Tao Yu, and Kilian Weinberger. 2019. Simplifying Graph Convolutional Networks. In _International Conference on Machine Learning_. 6861–6871.

- [36] Hua Wu, Qiuyan Wu, Guang Cheng, Shuyi Guo, Xiaoyan Hu, and Shen Yan. 2021. SFIM: Identify user behavior based on stable features. _Peer-to-Peer Networking and Applications_ 14, 6 (2021), 3674–3687.

- [37] Guorui Xie, Qing Li, and Yong Jiang. 2021. Self-attentive deep learning method for online traffic classification and its interpretability. _Computer Networks_ 196 (2021), 108267.

- [38] Keyulu Xu, Weihua Hu, Jure Leskovec, and Stefanie Jegelka. 2019. How Powerful are Graph Neural Networks?. In _International Conference on Learning Representations_.

- [39] Keyulu Xu, Chengtao Li, Yonglong Tian, Tomohiro Sonobe, Ken ichi Kawarabayashi, and Stefanie Jegelka. 2018. Representation Learning on Graphs with Jumping Knowledge Networks. In _International Conference on Machine Learning_. 5453–5462.

- [40] Shi-Jie Xu, Guang-Gang Geng, and Xiao-Bo Jin. 2022. Seeing Traffic Paths: Encrypted Traffic Classification With Path Signature Features. _IEEE Transactions on Information Forensics and Security_ 17, 1 (2022), 2166–2181.

- [41] Liang Yao, Chengsheng Mao, and Yuan Luo. 2019. Graph Convolutional Networks for Text Classification. In _AAAI Conference on Artifcial Intelligence_. 7370–7377.

- [42] Jiaxuan You, Zhitao Ying, and Jure Leskovec. 2020. Design Space for Graph Neural Networks. In _Conference on Neural Information Processing Systems_. 17009–17021.

- [43] Faiz Zaki, Firdaus Aff, Shukor Abd Razak, Abdullah Gani, and Nor Badrul Anuar. 2022. GRAIN: Granular multi-label encrypted traffic classification using classifier chain. _Computer Networks_ 213, 1 (2022), 109084.

- [44] Hui Zhang, Gaopeng Gou, Gang Xiong, Chang Liu, Yuewen Tan, and Ke Ye. 2021. Multi-granularity Mobile Encrypted Traffic Classification Based on Fusion Features. In _International Conference on Science of Cyber Security_. 154–170.

- [45] Songyang Zhang, Zeming Li, Shipeng Yan, Xuming He, and Jian Sun. 2021. Distribution Alignment: A Unifed Framework for Long-Tail Visual Recognition. In _Computer Vision and Pattern Recognition_. 2361–2370.

- [46] Juan Zheng, Zhiyong Zeng, and Tao Feng. 2022. GCN-ETA: High-Efciency Encrypted Malicious Traffic Detection. _Security and Communication Networks_ 2022, 1 (2022), 11 pages.

- [47] Wenbo Zheng, Chao Gou, Lan Yan, and Shaocong Mo. 2020. Learning to Classify: A Flow-Based Relation Network for Encrypted Traffic Classification. In _The Web Conference_. 13–22.

## Appendix A: THREAT MODEL AND ASSUMPTIONS
In this section, we present the threat model and assumptions. Normal users employ mobile apps to communicate with remote servers. The attacker is a passive observer (i.e., he cannot decrypt or modify packets). The attacker captures the packets of the target apps by compromising the device or snifng the network link. Then, the attacker analyzes the captured packets to infer the behaviors of normal users.

## Appendix B: LONG-TAILED DISTRIBUTION OF THE ISCX DATASET
We count the flow length on three datasets, i.e., ISCX-VPN, ISCXNonVPN and ISCX-NonTor datasets and the fgure below shows that the flow length generally obeys the long-tailed distribution.

<!-- Start of picture text -->
ISCX-VPN<br>ISCX-NonVPN<br>10000<br>ISCX-NonTor<br>8000<br>6000<br>4000<br>2000<br>0<br>0 250 500 750 1000 1250 1500 1750 2000<br>Flow Length Rank<br>Flow Length<br><!-- End of picture text -->

**Figure 4: Long-tailed Distribution of the Flow Length on ISCX-VPN, ISCX-NonVPN and ISCX-NonTor Datasets (Considering the amount of data, only part of the sorted data is shown)**
