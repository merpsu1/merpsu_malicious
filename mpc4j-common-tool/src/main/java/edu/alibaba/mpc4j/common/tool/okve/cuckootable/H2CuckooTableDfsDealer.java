package edu.alibaba.mpc4j.common.tool.okve.cuckootable;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * 2哈希-布谷鸟表深度优先搜索处理类。用于执行深度优先搜索，返回各个搜索的根节点，以及返回所有的环。
 *
 * @author Weiran Liu
 * @date 2021/09/09
 */
public class H2CuckooTableDfsDealer<T> {
    /**
     * 2哈希-布谷鸟表的顶点数量
     */
    private int numOfVertices;
    /**
     * 2哈希-布谷鸟表
     */
    private H2CuckooTable<T> h2CuckooTable;
    /**
     * 2哈希-布谷鸟图
     */
    private ArrayList<Set<T>> h2CuckooGraph;
    /**
     * 2哈希-布谷鸟图顶点集合
     */
    private Set<Integer> h2CuckooGraphVertexSet;
    /**
     * 深度优先搜索后得到的树
     */
    private H2CuckooTable<T> dfsH2CuckooTable;
    /**
     * 深度优先搜索后，各个图的根节点
     */
    private Map<Integer, ArrayList<T>> rootTraversalDataMap;
    /**
     * 深度优先搜索后，所有的back edge
     */
    private Set<T> backEdgeDataSet;
    /**
     * 遗留的数据集合
     */
    private Set<T> cycleEdgeDataSet;

    public H2CuckooTableDfsDealer() {
        // empty
    }

    public void findCycle(H2CuckooTable<T> h2CuckooTable) {
        this.h2CuckooTable = h2CuckooTable;
        this.h2CuckooGraph = h2CuckooTable.getCuckooGraph();
        this.numOfVertices = h2CuckooTable.getNumOfVertices();
        // 创建布谷鸟图的顶点集合，预先拿掉多余的顶点
        this.h2CuckooGraphVertexSet = IntStream.range(0, numOfVertices)
            .filter(vertex -> h2CuckooGraph.get(vertex).size() > 0)
            .boxed()
            .collect(Collectors.toSet());
        // 创建一个空的图
        dfsH2CuckooTable = new H2CuckooTable<>(numOfVertices);
        rootTraversalDataMap = new HashMap<>(numOfVertices);
        // 把所有的数据集都放进来
        backEdgeDataSet = new HashSet<>(h2CuckooTable.getDataSet());
        depthFirstSearch();
        findCycleEdgeSet();
    }

    private void depthFirstSearch() {
        Map<Integer, Boolean> traversalVertexMarkMap = new HashMap<>(h2CuckooGraphVertexSet.size());
        h2CuckooGraphVertexSet.forEach(vertex -> traversalVertexMarkMap.put(vertex, Boolean.FALSE));
        for (Integer root : h2CuckooGraphVertexSet) {
            if (!traversalVertexMarkMap.get(root)) {
                // 如果节点尚未被遍历，则执行深度优先搜搜
                ArrayList<T> traversalDataList = new ArrayList<>();
                depthFirstSearch(traversalDataList, traversalVertexMarkMap, root);
                rootTraversalDataMap.put(root, traversalDataList);
            }
            // 如果节点被mark过了，则在之前的深度优先搜索中已经被触达到，因此不能为root
        }
    }

    private void depthFirstSearch(ArrayList<T> traversalDataList, Map<Integer, Boolean> h2CuckooGraphVertexMarkMap,
        Integer vertex) {
        h2CuckooGraphVertexMarkMap.put(vertex, true);
        for (T data : h2CuckooGraph.get(vertex)) {
            Integer[] vertices = h2CuckooTable.getVertices(data);
            Integer target = vertex.equals(vertices[0]) ? vertices[1] : vertices[0];
            if (!h2CuckooGraphVertexMarkMap.get(target)) {
                // 如果找到了一个未访问过的节点，则把这条边添加到已经触达的边中，并在这条边的基础上继续执行深度优先搜索
                dfsH2CuckooTable.addData(vertices, data);
                backEdgeDataSet.remove(data);
                traversalDataList.add(data);
                depthFirstSearch(traversalDataList, h2CuckooGraphVertexMarkMap, target);
            }
        }
    }

    /**
     * 返回形成环的所有边。
     * <br/>注意：形成环的所有边不是一个2-core图.
     * <br/>例如图(9, 9), (9, 11), (11, 9)，形成环的图是(9, 9), (9, 11)，但2-core图是(9, 9), (9, 11), (11, 9)。
     */
    private void findCycleEdgeSet() {
        Map<Integer, Integer[]> edgeToSourceMap = new HashMap<>(numOfVertices);
        // 第一遍循环，找到所有back edge中起点的路径查找表
        for (T data : backEdgeDataSet) {
            Integer source = h2CuckooTable.getVertices(data)[0];
            if (!edgeToSourceMap.containsKey(source)) {
                edgeToSourceMap.put(source, findEdgesToTarget(source));
            }
        }
        // 第二遍循环，找到所有边
        cycleEdgeDataSet = new HashSet<>(dfsH2CuckooTable.getDataSet().size());
        for (T data : backEdgeDataSet) {
            // 先把back set自己添加进来
            cycleEdgeDataSet.add(data);
            Integer[] vertices = h2CuckooTable.getVertices(data);
            int source = vertices[0];
            Integer[] edgeToSource = edgeToSourceMap.get(source);
            int target = vertices[1];
            if (edgeToSource[target] != null) {
                for (int vertex = target; vertex != source; vertex = edgeToSource[vertex]) {
                    int nextVertex = edgeToSource[vertex];
                    Set<T> cycleDataSet = dfsH2CuckooTable.getDataSet(new Integer[] {vertex, nextVertex});
                    cycleEdgeDataSet.addAll(cycleDataSet);
                }
            }
        }
    }

    /**
     * 计算任意一个点到终点已知路径上的最后一个顶点查找表。
     *
     * @param target 终点。
     * @return 查找表。
     */
    private Integer[] findEdgesToTarget(Integer target) {
        boolean[] marked = new boolean[numOfVertices];
        // 注意，edgeTo找到的是从起点到一个顶点的已知路径上的最后一个顶点，因此应该用target进行深度优先搜索
        Integer[] edgeToTarget = new Integer[numOfVertices];
        findEdgesToTarget(marked, edgeToTarget, target);
        return edgeToTarget;
    }

    private void findEdgesToTarget(boolean[] marked, Integer[] edgeTo, Integer vertex) {
        marked[vertex] = true;
        for (T data : dfsH2CuckooTable.getCuckooGraph().get(vertex)) {
            Integer[] vertices = h2CuckooTable.getVertices(data);
            Integer target = vertex.equals(vertices[0]) ? vertices[1] : vertices[0];
            if (!marked[target]) {
                // 如果找到了一个未访问过的节点，则把这条边添加到已经触达的边中，并在这条边的基础上继续执行深度优先搜索
                edgeTo[target] = vertex;
                findEdgesToTarget(marked, edgeTo, target);
            }
        }
    }

    /**
     * 返回深度优先搜索的搜索路径映射，其中key为根节点，后续的列表为搜索路径。
     *
     * @return 搜索路径映射。
     */
    public Map<Integer, ArrayList<T>> getRootTraversalDataMap() {
        return rootTraversalDataMap;
    }

    /**
     * 返回循环边集合。
     *
     * @return 循环边集合。
     */
    public Set<T> getCycleEdgeDataSet() {
        return cycleEdgeDataSet;
    }
}
