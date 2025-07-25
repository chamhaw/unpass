package report

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/yourorg/unpass/internal/types"
)

// TableGenerator 表格报告生成器
type TableGenerator struct{}

func NewTableGenerator() *TableGenerator {
	return &TableGenerator{}
}

// Generate 生成包含凭据标题的表格报告
func (g *TableGenerator) Generate(writer io.Writer, report *types.AuditReport) error {
	// 报告标题
	fmt.Fprintln(writer, "Name:         unpass-security-audit")
	fmt.Fprintln(writer, "Namespace:    security")
	fmt.Fprintf(writer, "Created:      %s\n", report.Timestamp.Format("Mon, 02 Jan 2006 15:04:05 MST"))
	fmt.Fprintln(writer)

	// 基本统计
	fmt.Fprintln(writer, "Summary:")
	fmt.Fprintf(writer, "  Total Credentials:    %d\n", report.Summary.TotalCredentials)
	fmt.Fprintf(writer, "  Issues Found:         %d\n", report.Summary.IssuesFound)
	fmt.Fprintln(writer)

	// 问题统计
	if len(report.Summary.ByType) > 0 {
		fmt.Fprintln(writer, "Issues by Category:")

		if count, exists := report.Summary.ByType[types.DetectionMissing2FA]; exists && count > 0 {
			fmt.Fprintf(writer, "  Missing 2FA:          %d\n", count)
		}

		if count, exists := report.Summary.ByType[types.DetectionMissingPasskey]; exists && count > 0 {
			fmt.Fprintf(writer, "  Missing Passkey:      %d\n", count)
		}
		fmt.Fprintln(writer)
	}

	// 详细问题列表
	if len(report.Results) > 0 {
		// 按类型分组
		twofaResults := []types.DetectionResult{}
		passkeyResults := []types.DetectionResult{}

		for _, result := range report.Results {
			switch result.Type {
			case types.DetectionMissing2FA:
				twofaResults = append(twofaResults, result)
			case types.DetectionMissingPasskey:
				passkeyResults = append(passkeyResults, result)
			}
		}

		// 2FA问题
		if len(twofaResults) > 0 {
			fmt.Fprintf(writer, "Two-Factor Authentication Issues (%d total):\n", len(twofaResults))
			g.generateClusteredResults(writer, twofaResults)
			fmt.Fprintln(writer)
		}

		// Passkey问题
		if len(passkeyResults) > 0 {
			fmt.Fprintf(writer, "Passkey Authentication Issues (%d total):\n", len(passkeyResults))
			g.generateClusteredResults(writer, passkeyResults)
			fmt.Fprintln(writer)
		}
	}

	return nil
}

// generateClusteredResults 生成基于相似度聚类的结果
func (g *TableGenerator) generateClusteredResults(writer io.Writer, results []types.DetectionResult) {
	if len(results) == 0 {
		return
	}

	// 提取所有标题用于聚类
	titles := make([]string, len(results))
	for i, result := range results {
		titles[i] = result.Title
	}

	// 执行聚类
	clusters := g.clusterBySimilarity(titles, results)

	// 显示聚类结果
	for _, cluster := range clusters {
		clusterName := g.generateClusterName(cluster.Results)
		fmt.Fprintf(writer, "\n[%s] (%d items)\n", clusterName, len(cluster.Results))

		// 按标题排序组内结果
		sort.Slice(cluster.Results, func(i, j int) bool {
			return cluster.Results[i].Title < cluster.Results[j].Title
		})

		for _, result := range cluster.Results {
			domain := g.extractDomain(result.Metadata)
			fmt.Fprintf(writer, "  %s", result.Title)
			if domain != "-" && domain != "" {
				fmt.Fprintf(writer, " (%s)", domain)
			}
			fmt.Fprintln(writer)
		}
	}
}

// Cluster 聚类结构
type Cluster struct {
	Results  []types.DetectionResult
	Centroid []string // 聚类中心的关键词
}

// clusterBySimilarity 基于相似度进行聚类
func (g *TableGenerator) clusterBySimilarity(titles []string, results []types.DetectionResult) []Cluster {
	if len(results) <= 3 {
		// 数量太少，直接返回一个聚类
		return []Cluster{{Results: results}}
	}

	// 首先按domain强制分组
	domainGroups := g.groupByDomain(results)

	// 在每个domain组内按title相似度细分
	var finalClusters []Cluster
	var individualItems []types.DetectionResult // 收集单项，每个作为独立聚类

	for _, group := range domainGroups {
		if len(group.Results) == 1 {
			// 只有一个项目的域名组，作为独立聚类
			individualItems = append(individualItems, group.Results...)
		} else if len(group.Results) <= 6 {
			// 中小型组，直接作为一个聚类
			finalClusters = append(finalClusters, group)
		} else {
			// 大组：检查是否有明显的服务标识，如果有则保持聚类
			if g.hasSameServiceIdentity(group.Results) {
				// 有明显的相同服务标识（如AWS），保持聚类不拆分
				finalClusters = append(finalClusters, group)
			} else {
				// 没有明显服务标识，进行title相似度细分
				subClusters := g.clusterByTitleSimilarity(group.Results)

				for _, subCluster := range subClusters {
					if len(subCluster.Results) >= 2 && len(subCluster.Results) <= 8 { // 限制子聚类大小
						finalClusters = append(finalClusters, subCluster)
					} else if len(subCluster.Results) == 1 {
						// 单项聚类作为独立项
						individualItems = append(individualItems, subCluster.Results...)
					} else {
						// 过大的子聚类进一步拆分
						splitSubClusters := g.splitLargeCluster(subCluster.Results)
						finalClusters = append(finalClusters, splitSubClusters...)
					}
				}
			}
		}
	}

	// 单项都作为独立聚类，不进行任何合并
	for _, item := range individualItems {
		finalClusters = append(finalClusters, Cluster{Results: []types.DetectionResult{item}})
	}

	// 最终限制聚类数量 - 如果太多，只合并最小的几个
	if len(finalClusters) > 15 {
		finalClusters = g.mergeOnlySmallest(finalClusters, 15)
	}

	return finalClusters
}

// hasSameServiceIdentity 检查是否有相同的服务标识
func (g *TableGenerator) hasSameServiceIdentity(results []types.DetectionResult) bool {
	if len(results) <= 1 {
		return false
	}

	// 提取所有关键词并统计频率
	wordFreq := make(map[string]int)
	totalItems := len(results)

	for _, result := range results {
		keywords := g.extractKeywords(result.Title)
		for _, keyword := range keywords {
			if len(keyword) >= 3 { // 只考虑有意义的关键词
				wordFreq[keyword]++
			}
		}
	}

	// 检查是否有关键词在大部分项目中出现
	for _, freq := range wordFreq {
		// 如果某个关键词在70%以上的项目中出现，认为有相同服务标识
		if float64(freq)/float64(totalItems) >= 0.7 {
			return true
		}
	}

	// 检查域名的一致性
	if len(results) > 0 {
		firstDomain := g.extractMainDomain(g.extractDomain(results[0].Metadata))
		if firstDomain != "" && firstDomain != "unknown" {
			// 检查域名在大部分项目中是否一致
			domainMatchCount := 0
			for _, result := range results {
				domain := g.extractMainDomain(g.extractDomain(result.Metadata))
				if domain == firstDomain {
					domainMatchCount++
				}
			}

			// 如果80%以上项目使用相同域名，认为应该保持聚类
			if float64(domainMatchCount)/float64(totalItems) >= 0.8 {
				return true
			}
		}
	}

	return false
}

// mergeOnlySmallest 只合并最小的聚类，避免过度合并
func (g *TableGenerator) mergeOnlySmallest(clusters []Cluster, maxClusters int) []Cluster {
	if len(clusters) <= maxClusters {
		return clusters
	}

	// 按大小排序，小的在前
	sort.Slice(clusters, func(i, j int) bool {
		return len(clusters[i].Results) < len(clusters[j].Results)
	})

	// 只合并单项聚类
	var singleItemClusters []types.DetectionResult
	var multiItemClusters []Cluster

	for _, cluster := range clusters {
		if len(cluster.Results) == 1 {
			singleItemClusters = append(singleItemClusters, cluster.Results...)
		} else {
			multiItemClusters = append(multiItemClusters, cluster)
		}
	}

	// 保留所有多项聚类
	finalClusters := multiItemClusters

	// 单项聚类按需合并
	if len(singleItemClusters) > 0 {
		remaining := maxClusters - len(multiItemClusters)
		if remaining > 0 && len(singleItemClusters) > remaining {
			// 需要合并部分单项
			chunkSize := len(singleItemClusters) / remaining
			if chunkSize < 1 {
				chunkSize = 1
			}

			for i := 0; i < len(singleItemClusters); i += chunkSize {
				end := i + chunkSize
				if end > len(singleItemClusters) {
					end = len(singleItemClusters)
				}
				finalClusters = append(finalClusters, Cluster{Results: singleItemClusters[i:end]})
			}
		} else {
			// 每个单项都作为独立聚类
			for _, item := range singleItemClusters {
				finalClusters = append(finalClusters, Cluster{Results: []types.DetectionResult{item}})
			}
		}
	}

	return finalClusters
}

// reorganizeByDomain 按域名重新组织大量小组
func (g *TableGenerator) reorganizeByDomain(items []types.DetectionResult) []Cluster {
	// 按域名分组
	domainGroups := make(map[string][]types.DetectionResult)

	for _, item := range items {
		domain := g.extractMainDomain(g.extractDomain(item.Metadata))
		if domain == "" || domain == "unknown" {
			domain = "misc"
		}
		domainGroups[domain] = append(domainGroups[domain], item)
	}

	var clusters []Cluster
	var miscItems []types.DetectionResult

	// 处理各个域名组
	for domain, group := range domainGroups {
		if len(group) >= 2 && len(group) <= 8 {
			// 合适大小的组，直接作为聚类
			clusters = append(clusters, Cluster{Results: group})
		} else if len(group) > 8 {
			// 过大的组，按服务名进一步细分
			subClusters := g.subdivideByService(group)
			clusters = append(clusters, subClusters...)
		} else {
			// 单项组，加入杂项
			if domain != "misc" {
				miscItems = append(miscItems, group...)
			} else {
				miscItems = append(miscItems, group...)
			}
		}
	}

	// 处理杂项
	if len(miscItems) > 0 {
		if len(miscItems) <= 6 {
			clusters = append(clusters, Cluster{Results: miscItems})
		} else {
			// 杂项太多，按块分割
			chunkSize := 5
			for i := 0; i < len(miscItems); i += chunkSize {
				end := i + chunkSize
				if end > len(miscItems) {
					end = len(miscItems)
				}
				clusters = append(clusters, Cluster{Results: miscItems[i:end]})
			}
		}
	}

	return clusters
}

// subdivideByService 按服务名细分大组
func (g *TableGenerator) subdivideByService(items []types.DetectionResult) []Cluster {
	if len(items) <= 6 {
		return []Cluster{{Results: items}}
	}

	// 基于服务关键词分组
	serviceGroups := make(map[string][]types.DetectionResult)
	processed := make(map[int]bool)

	for i, item := range items {
		if processed[i] {
			continue
		}

		keywords := g.extractKeywords(item.Title)
		serviceKey := g.generateServiceKey(keywords, item.Title)

		group := []types.DetectionResult{item}
		processed[i] = true

		// 寻找相似的项目
		for j, otherItem := range items {
			if processed[j] || i == j {
				continue
			}

			otherKeywords := g.extractKeywords(otherItem.Title)
			if g.isSimilarService(keywords, otherKeywords) {
				group = append(group, otherItem)
				processed[j] = true
			}
		}

		serviceGroups[serviceKey] = group
	}

	var clusters []Cluster
	for _, group := range serviceGroups {
		if len(group) >= 2 && len(group) <= 6 {
			clusters = append(clusters, Cluster{Results: group})
		} else if len(group) == 1 {
			clusters = append(clusters, Cluster{Results: group})
		} else {
			// 仍然过大的组，强制分割
			subClusters := g.splitLargeCluster(group)
			clusters = append(clusters, subClusters...)
		}
	}

	return clusters
}

// generateServiceKey 生成服务键
func (g *TableGenerator) generateServiceKey(keywords []string, title string) string {
	if len(keywords) == 0 {
		return strings.ToLower(title) // 确保service key也是小写
	}

	// 使用第一个有意义的关键词（已经是小写）
	for _, keyword := range keywords {
		if len(keyword) >= 3 {
			return keyword
		}
	}

	return keywords[0]
}

// isSimilarService 检查服务相似性
func (g *TableGenerator) isSimilarService(keywords1, keywords2 []string) bool {
	if len(keywords1) == 0 || len(keywords2) == 0 {
		return false
	}

	// 检查关键词重叠（keywords已经是小写）
	for _, k1 := range keywords1 {
		for _, k2 := range keywords2 {
			if k1 == k2 || (len(k1) >= 4 && len(k2) >= 4 && (strings.Contains(k1, k2) || strings.Contains(k2, k1))) {
				return true
			}
		}
	}

	return false
}

// performSecondaryClustering 对小组进行二次聚类
func (g *TableGenerator) performSecondaryClustering(items []types.DetectionResult) []Cluster {
	if len(items) <= 2 {
		return []Cluster{{Results: items}}
	}

	// 先进行基于关键词的强制分组
	keywordClusters := g.groupByKeywords(items)

	var finalClusters []Cluster
	var unclusteredItems []types.DetectionResult

	// 处理关键词分组的结果
	for _, cluster := range keywordClusters {
		if len(cluster.Results) >= 2 {
			finalClusters = append(finalClusters, cluster)
		} else {
			unclusteredItems = append(unclusteredItems, cluster.Results...)
		}
	}

	// 对未聚类的项目进行更深度的分析，但限制合并规模
	if len(unclusteredItems) > 3 {
		deepClusters := g.performDeepClustering(unclusteredItems)

		for _, cluster := range deepClusters {
			if len(cluster.Results) >= 2 && len(cluster.Results) <= 8 { // 限制聚类大小
				finalClusters = append(finalClusters, cluster)
			} else if len(cluster.Results) == 1 {
				// 尝试合并到现有的小聚类中，但有严格限制
				merged := false
				for i, existingCluster := range finalClusters {
					if len(existingCluster.Results) < 3 { // 只合并到很小的聚类
						// 检查是否可以合并（使用更严格的条件）
						if g.canMergeStrictly(cluster.Results, existingCluster.Results) {
							finalClusters[i].Results = append(finalClusters[i].Results, cluster.Results...)
							merged = true
							break
						}
					}
				}

				if !merged {
					// 单项保留为独立聚类
					finalClusters = append(finalClusters, cluster)
				}
			} else {
				// 太大的聚类直接拆分
				splitClusters := g.splitLargeCluster(cluster.Results)
				finalClusters = append(finalClusters, splitClusters...)
			}
		}
	} else if len(unclusteredItems) > 0 {
		// 剩余项目太少，每个作为独立聚类
		for _, item := range unclusteredItems {
			finalClusters = append(finalClusters, Cluster{Results: []types.DetectionResult{item}})
		}
	}

	return finalClusters
}

// splitLargeCluster 拆分过大的聚类
func (g *TableGenerator) splitLargeCluster(items []types.DetectionResult) []Cluster {
	if len(items) <= 6 {
		return []Cluster{{Results: items}}
	}

	// 按域名重新分组
	domainGroups := make(map[string][]types.DetectionResult)

	for _, item := range items {
		domain := g.extractMainDomain(g.extractDomain(item.Metadata))
		if domain == "" || domain == "unknown" {
			domain = "misc"
		}
		domainGroups[domain] = append(domainGroups[domain], item)
	}

	var clusters []Cluster
	var miscItems []types.DetectionResult

	// 将同域名且数量足够的组作为独立聚类
	for _, group := range domainGroups {
		if len(group) >= 2 && len(group) <= 6 {
			clusters = append(clusters, Cluster{Results: group})
		} else {
			miscItems = append(miscItems, group...)
		}
	}

	// 剩余项目作为单独的聚类
	if len(miscItems) > 0 {
		if len(miscItems) <= 6 {
			clusters = append(clusters, Cluster{Results: miscItems})
		} else {
			// 进一步拆分
			chunkSize := 4
			for i := 0; i < len(miscItems); i += chunkSize {
				end := i + chunkSize
				if end > len(miscItems) {
					end = len(miscItems)
				}
				clusters = append(clusters, Cluster{Results: miscItems[i:end]})
			}
		}
	}

	return clusters
}

// canMergeStrictly 严格的合并检查
func (g *TableGenerator) canMergeStrictly(items1, items2 []types.DetectionResult) bool {
	// 如果任一聚类为空，不合并
	if len(items1) == 0 || len(items2) == 0 {
		return false
	}

	// 限制合并后的大小
	if len(items1)+len(items2) > 5 {
		return false
	}

	// 检查是否所有项目都来自相同域名
	domains1 := make(map[string]bool)
	domains2 := make(map[string]bool)

	for _, item := range items1 {
		domain := g.extractMainDomain(g.extractDomain(item.Metadata))
		if domain != "" && domain != "unknown" {
			domains1[domain] = true
		}
	}

	for _, item := range items2 {
		domain := g.extractMainDomain(g.extractDomain(item.Metadata))
		if domain != "" && domain != "unknown" {
			domains2[domain] = true
		}
	}

	// 必须有共同域名
	hasCommonDomain := false
	for domain := range domains1 {
		if domains2[domain] {
			hasCommonDomain = true
			break
		}
	}

	if !hasCommonDomain {
		return false
	}

	// 检查聚类间的相似性（使用更严格的条件）
	for _, item1 := range items1 {
		keywords1 := g.extractKeywords(item1.Title)

		for _, item2 := range items2 {
			keywords2 := g.extractKeywords(item2.Title)

			// 必须有明确的关键词重叠
			overlap := 0
			for _, k1 := range keywords1 {
				for _, k2 := range keywords2 {
					if k1 == k2 {
						overlap++
						break
					}
				}
			}

			if overlap >= 1 {
				return true
			}
		}
	}

	return false
}

// performDeepClustering 执行深度聚类分析
func (g *TableGenerator) performDeepClustering(items []types.DetectionResult) []Cluster {
	if len(items) <= 2 {
		return []Cluster{{Results: items}}
	}

	// 使用更激进的相似度检测
	clusters := make([]Cluster, 0)
	processed := make(map[int]bool)

	for i, item := range items {
		if processed[i] {
			continue
		}

		cluster := Cluster{Results: []types.DetectionResult{item}}
		processed[i] = true

		keywords1 := g.extractKeywords(item.Title)
		domain1 := g.extractMainDomain(g.extractDomain(item.Metadata))

		// 寻找相似的项目
		for j, otherItem := range items {
			if processed[j] || i == j {
				continue
			}

			keywords2 := g.extractKeywords(otherItem.Title)
			domain2 := g.extractMainDomain(g.extractDomain(otherItem.Metadata))

			// 使用更宽松的相似度检测
			if g.isDeepSimilar(keywords1, keywords2, domain1, domain2, item.Title, otherItem.Title) {
				cluster.Results = append(cluster.Results, otherItem)
				processed[j] = true
			}
		}

		clusters = append(clusters, cluster)
	}

	return clusters
}

// isDeepSimilar 深度相似性检测
func (g *TableGenerator) isDeepSimilar(keywords1, keywords2 []string, domain1, domain2, title1, title2 string) bool {
	// 1. 检查是否是同一服务（使用现有逻辑）
	if g.isSameService(keywords1, keywords2, domain1, domain2) {
		return true
	}

	// 2. 检查标题直接相似性（编辑距离）
	if g.isTitleSimilar(title1, title2) {
		return true
	}

	// 3. 检查域名相同
	if domain1 == domain2 && domain1 != "" && domain1 != "unknown" {
		return true
	}

	// 4. 检查关键词高度重叠
	overlap := 0
	for _, k1 := range keywords1 {
		for _, k2 := range keywords2 {
			if k1 == k2 || strings.Contains(k1, k2) || strings.Contains(k2, k1) {
				overlap++
				break
			}
		}
	}

	minKeywords := len(keywords1)
	if len(keywords2) < minKeywords {
		minKeywords = len(keywords2)
	}

	if minKeywords > 0 && float64(overlap)/float64(minKeywords) >= 0.6 {
		return true
	}

	return false
}

// isTitleSimilar 检查标题相似性
func (g *TableGenerator) isTitleSimilar(title1, title2 string) bool {
	// 转换为小写并移除特殊字符
	clean1 := strings.ToLower(g.cleanTitleForComparison(title1))
	clean2 := strings.ToLower(g.cleanTitleForComparison(title2))

	// 如果标题很短且完全相同
	if len(clean1) <= 10 && len(clean2) <= 10 && clean1 == clean2 {
		return true
	}

	// 检查包含关系
	if len(clean1) >= 3 && len(clean2) >= 3 {
		if strings.Contains(clean1, clean2) || strings.Contains(clean2, clean1) {
			return true
		}
	}

	// 检查共同的长子串
	if g.hasCommonSubstring(clean1, clean2, 4) {
		return true
	}

	return false
}

// cleanTitleForComparison 清理标题用于比较
func (g *TableGenerator) cleanTitleForComparison(title string) string {
	// 移除常见的修饰符
	cleaned := title
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "_", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")
	cleaned = strings.ReplaceAll(cleaned, "🇺🇸", "")
	cleaned = strings.ReplaceAll(cleaned, "🇨🇳", "")
	cleaned = strings.ReplaceAll(cleaned, "🇭🇰", "")

	// 移除数字后缀
	if len(cleaned) > 3 {
		// 移除末尾的数字
		for i := len(cleaned) - 1; i >= 0; i-- {
			if cleaned[i] >= '0' && cleaned[i] <= '9' {
				cleaned = cleaned[:i]
			} else {
				break
			}
		}
	}

	return cleaned
}

// hasCommonSubstring 检查是否有共同的长子串
func (g *TableGenerator) hasCommonSubstring(s1, s2 string, minLen int) bool {
	if len(s1) < minLen || len(s2) < minLen {
		return false
	}

	for i := 0; i <= len(s1)-minLen; i++ {
		substr := s1[i : i+minLen]
		if strings.Contains(s2, substr) {
			return true
		}
	}

	return false
}

// canMergeClusters 检查是否可以合并两个聚类
func (g *TableGenerator) canMergeClusters(items1, items2 []types.DetectionResult) bool {
	// 如果任一聚类为空，不合并
	if len(items1) == 0 || len(items2) == 0 {
		return false
	}

	// 检查聚类间的相似性
	for _, item1 := range items1 {
		keywords1 := g.extractKeywords(item1.Title)
		domain1 := g.extractMainDomain(g.extractDomain(item1.Metadata))

		for _, item2 := range items2 {
			keywords2 := g.extractKeywords(item2.Title)
			domain2 := g.extractMainDomain(g.extractDomain(item2.Metadata))

			if g.isDeepSimilar(keywords1, keywords2, domain1, domain2, item1.Title, item2.Title) {
				return true
			}
		}
	}

	return false
}

// groupByKeywords 基于关键词进行强制分组
func (g *TableGenerator) groupByKeywords(items []types.DetectionResult) []Cluster {
	// 提取每个项目的关键词
	keywordGroups := make(map[string][]types.DetectionResult)
	processed := make(map[int]bool)

	for i, item := range items {
		if processed[i] {
			continue
		}

		// 提取主要关键词
		keywords := g.extractKeywords(item.Title)
		domain := g.extractMainDomain(g.extractDomain(item.Metadata))

		// 寻找相似的项目
		var group []types.DetectionResult
		group = append(group, item)
		processed[i] = true

		for j, otherItem := range items {
			if processed[j] || i == j {
				continue
			}

			otherKeywords := g.extractKeywords(otherItem.Title)
			otherDomain := g.extractMainDomain(g.extractDomain(otherItem.Metadata))

			// 检查是否应该分组
			if g.shouldGroupByKeywords(keywords, otherKeywords, domain, otherDomain) {
				group = append(group, otherItem)
				processed[j] = true
			}
		}

		if len(group) > 0 {
			// 生成分组键
			groupKey := g.generateGroupKey(group)
			keywordGroups[groupKey] = group
		}
	}

	// 转换为Cluster格式
	var clusters []Cluster
	for _, group := range keywordGroups {
		clusters = append(clusters, Cluster{Results: group})
	}

	return clusters
}

// extractKeywords 提取标题中的关键词
func (g *TableGenerator) extractKeywords(title string) []string {
	words := g.tokenize(title)
	var keywords []string

	for _, word := range words {
		// 过滤掉太短或太常见的词，并转换为小写
		if len(word) >= 3 && !g.isStopWord(word) {
			keywords = append(keywords, strings.ToLower(word)) // 统一转换为小写
		}
	}

	return keywords
}

// shouldGroupByKeywords 判断是否应该基于关键词分组
func (g *TableGenerator) shouldGroupByKeywords(keywords1, keywords2 []string, domain1, domain2 string) bool {
	// 如果域名相同，更容易分组
	sameDomain := domain1 == domain2 && domain1 != "" && domain1 != "unknown"

	// 特殊处理：检查是否是明显的同一服务
	if g.isSameService(keywords1, keywords2, domain1, domain2) {
		return true
	}

	// 计算关键词重叠度（已经在extractKeywords中转换为小写）
	overlap := 0
	maxOverlap := 0

	// 精确匹配
	for _, k1 := range keywords1 {
		for _, k2 := range keywords2 {
			if k1 == k2 { // 现在都是小写，可以直接比较
				overlap++
				break
			}
		}
	}
	maxOverlap = overlap

	// 模糊匹配（包含关系）
	fuzzyOverlap := 0
	for _, k1 := range keywords1 {
		for _, k2 := range keywords2 {
			if len(k1) >= 3 && len(k2) >= 3 {
				if strings.Contains(k1, k2) || strings.Contains(k2, k1) {
					fuzzyOverlap++
					break
				}
			}
		}
	}

	if fuzzyOverlap > maxOverlap {
		maxOverlap = fuzzyOverlap
	}

	minKeywords := len(keywords1)
	if len(keywords2) < minKeywords {
		minKeywords = len(keywords2)
	}

	if minKeywords == 0 {
		return sameDomain
	}

	overlapRatio := float64(maxOverlap) / float64(minKeywords)

	// 调整分组阈值 - 更宽松的条件
	if sameDomain {
		return overlapRatio >= 0.2 || maxOverlap >= 1 // 同域名要求很低
	} else {
		// 不同域名但有相同服务名称
		return overlapRatio >= 0.4 || maxOverlap >= 2
	}
}

// isSameService 检查是否是同一服务的不同变体
func (g *TableGenerator) isSameService(keywords1, keywords2 []string, domain1, domain2 string) bool {
	// 检查关键词直接重叠
	for _, k1 := range keywords1 {
		for _, k2 := range keywords2 {
			if k1 == k2 {
				return true
			}
			// 检查包含关系（用于处理服务名的变体）
			if len(k1) >= 4 && len(k2) >= 4 {
				if strings.Contains(k1, k2) || strings.Contains(k2, k1) {
					return true
				}
			}
		}
	}

	// 检查域名相似性
	if domain1 != "" && domain2 != "" && domain1 != "unknown" && domain2 != "unknown" {
		// 提取主域名部分
		d1Parts := strings.Split(domain1, ".")
		d2Parts := strings.Split(domain2, ".")

		if len(d1Parts) > 0 && len(d2Parts) > 0 {
			mainDomain1 := strings.ToLower(d1Parts[0])
			mainDomain2 := strings.ToLower(d2Parts[0])

			// 如果主域名相同
			if mainDomain1 == mainDomain2 {
				return true
			}

			// 检查是否是相关的子域名（启发式）
			// 如果两个域名有共同的较长子串，可能是相关域名
			if g.hasCommonDomainSubstring(mainDomain1, mainDomain2, 4) {
				return true
			}
		}
	}

	return false
}

// hasCommonDomainSubstring 检查域名是否有共同子串
func (g *TableGenerator) hasCommonDomainSubstring(domain1, domain2 string, minLen int) bool {
	if len(domain1) < minLen || len(domain2) < minLen {
		return false
	}

	// 检查较长的共同子串
	for i := 0; i <= len(domain1)-minLen; i++ {
		substr := domain1[i : i+minLen]
		if strings.Contains(domain2, substr) {
			return true
		}
	}

	return false
}

// generateGroupKey 为分组生成键
func (g *TableGenerator) generateGroupKey(group []types.DetectionResult) string {
	if len(group) == 0 {
		return "empty"
	}

	// 找出最频繁的关键词
	wordFreq := make(map[string]int)
	domainFreq := make(map[string]int)

	for _, item := range group {
		keywords := g.extractKeywords(item.Title)
		for _, keyword := range keywords {
			wordFreq[keyword]++
		}

		domain := g.extractMainDomain(g.extractDomain(item.Metadata))
		if domain != "" && domain != "unknown" {
			domainFreq[domain]++
		}
	}

	// 找到最频繁的词
	maxWordFreq := 0
	dominantWord := ""
	for word, freq := range wordFreq {
		if freq > maxWordFreq {
			maxWordFreq = freq
			dominantWord = word
		}
	}

	// 找到最频繁的域名
	maxDomainFreq := 0
	dominantDomain := ""
	for domain, freq := range domainFreq {
		if freq > maxDomainFreq {
			maxDomainFreq = freq
			dominantDomain = domain
		}
	}

	// 生成组键
	if dominantWord != "" && maxWordFreq >= len(group)/2 {
		return dominantWord
	} else if dominantDomain != "" {
		return dominantDomain
	} else {
		return strings.ToLower(group[0].Title)
	}
}

// performVectorClustering 执行向量相似度聚类
func (g *TableGenerator) performVectorClustering(items []types.DetectionResult) []Cluster {
	if len(items) <= 2 {
		return []Cluster{{Results: items}}
	}

	// 提取标题和域名信息
	titles := make([]string, len(items))
	domains := make([]string, len(items))

	for i, item := range items {
		titles[i] = item.Title
		domains[i] = g.extractMainDomain(g.extractDomain(item.Metadata))
	}

	// 构建组合向量：title权重0.7，domain权重0.3
	combinedVectors := g.buildCombinedVectorsForSecondary(titles, domains)

	// 计算相似度矩阵
	similarities := g.calculateSimilarityMatrix(combinedVectors)

	// 执行聚类，使用适中的阈值
	clusters := g.hierarchicalClustering(items, similarities, 0.3)

	return clusters
}

// buildCombinedVectorsForSecondary 为二次聚类构建组合向量
func (g *TableGenerator) buildCombinedVectorsForSecondary(titles []string, domains []string) []map[string]float64 {
	// 构建title向量
	titleVectors := g.buildTFIDFVectors(titles)

	// 构建domain向量
	domainVectors := g.buildTFIDFVectors(domains)

	// 组合向量：title权重0.6，domain权重0.4
	combinedVectors := make([]map[string]float64, len(titles))
	for i := 0; i < len(titles); i++ {
		combined := make(map[string]float64)

		// 添加title特征（权重0.6）
		for word, score := range titleVectors[i] {
			combined["title_"+word] = score * 0.6
		}

		// 添加domain特征（权重0.4）
		for word, score := range domainVectors[i] {
			combined["domain_"+word] = score * 0.4
		}

		combinedVectors[i] = combined
	}

	return combinedVectors
}

// groupSmallItemsByCategory 将小项目按类别分组
func (g *TableGenerator) groupSmallItemsByCategory(items []types.DetectionResult) []Cluster {
	// 按服务类型分类的关键词
	categories := map[string][]string{
		"Cloud & Infrastructure": {"aws", "amazon", "google", "microsoft", "azure", "cloudflare", "digitalocean", "vultr", "linode", "oracle"},
		"Developer Tools":        {"github", "gitlab", "bitbucket", "docker", "jetbrains", "stackoverflow", "redis", "mongodb"},
		"Social & Communication": {"twitter", "facebook", "instagram", "linkedin", "discord", "slack", "telegram", "whatsapp", "wechat", "qq"},
		"Gaming & Entertainment": {"steam", "epic", "playstation", "xbox", "nintendo", "twitch", "youtube", "spotify", "netflix"},
		"Financial & Payment":    {"paypal", "stripe", "bank", "visa", "mastercard", "alipay", "wechatpay"},
		"Email & Productivity":   {"gmail", "outlook", "yahoo", "163", "126", "notion", "evernote", "dropbox", "box"},
	}

	categoryGroups := make(map[string][]types.DetectionResult)
	uncategorized := []types.DetectionResult{}

	for _, item := range items {
		categorized := false
		itemText := strings.ToLower(item.Title + " " + g.extractDomain(item.Metadata))

		for categoryName, keywords := range categories {
			for _, keyword := range keywords {
				if strings.Contains(itemText, keyword) {
					categoryGroups[categoryName] = append(categoryGroups[categoryName], item)
					categorized = true
					break
				}
			}
			if categorized {
				break
			}
		}

		if !categorized {
			uncategorized = append(uncategorized, item)
		}
	}

	var clusters []Cluster

	// 转换分类结果为聚类，只保留有足够项目的类别
	for _, group := range categoryGroups {
		if len(group) >= 2 {
			clusters = append(clusters, Cluster{Results: group})
		} else {
			uncategorized = append(uncategorized, group...)
		}
	}

	// 处理未分类的项目
	if len(uncategorized) > 0 {
		clusters = append(clusters, Cluster{Results: uncategorized})
	}

	return clusters
}

// groupByDomain 按domain分组
func (g *TableGenerator) groupByDomain(results []types.DetectionResult) []Cluster {
	domainMap := make(map[string][]types.DetectionResult)

	for _, result := range results {
		domain := g.extractDomain(result.Metadata)
		mainDomain := g.extractMainDomain(domain)
		if mainDomain == "" {
			mainDomain = "unknown"
		}
		domainMap[mainDomain] = append(domainMap[mainDomain], result)
	}

	var clusters []Cluster
	for _, group := range domainMap {
		clusters = append(clusters, Cluster{Results: group})
	}

	return clusters
}

// clusterByTitleSimilarity 在同domain内按title相似度聚类
func (g *TableGenerator) clusterByTitleSimilarity(results []types.DetectionResult) []Cluster {
	if len(results) <= 3 {
		return []Cluster{{Results: results}}
	}

	// 提取标题
	titles := make([]string, len(results))
	for i, result := range results {
		titles[i] = result.Title
	}

	// 构建title向量
	titleVectors := g.buildTFIDFVectors(titles)

	// 计算相似度矩阵
	similarities := g.calculateSimilarityMatrix(titleVectors)

	// 执行层次聚类，使用更高的阈值因为是同domain内
	clusters := g.hierarchicalClustering(results, similarities, 0.3)

	return clusters
}

// mergeSmallestClusters 合并最小的聚类
func (g *TableGenerator) mergeSmallestClusters(clusters []Cluster, targetCount int) []Cluster {
	if len(clusters) <= targetCount {
		return clusters
	}

	// 按聚类大小排序
	sort.Slice(clusters, func(i, j int) bool {
		return len(clusters[i].Results) > len(clusters[j].Results)
	})

	// 保留前targetCount-1个最大的聚类，其余合并到一个"Others"组
	result := clusters[:targetCount-1]

	// 合并剩余的小聚类
	othersCluster := Cluster{Results: []types.DetectionResult{}}
	for i := targetCount - 1; i < len(clusters); i++ {
		othersCluster.Results = append(othersCluster.Results, clusters[i].Results...)
	}

	if len(othersCluster.Results) > 0 {
		result = append(result, othersCluster)
	}

	return result
}

// buildCombinedVectors 构建组合TF-IDF向量（title + domain）
func (g *TableGenerator) buildCombinedVectors(titles []string, results []types.DetectionResult) []map[string]float64 {
	// 提取domain信息
	domains := make([]string, len(results))
	for i, result := range results {
		domain := g.extractDomain(result.Metadata)
		// 简化domain，提取主要部分
		domains[i] = g.extractMainDomain(domain)
	}

	// 构建title向量
	titleVectors := g.buildTFIDFVectors(titles)

	// 构建domain向量
	domainVectors := g.buildTFIDFVectors(domains)

	// 组合向量：title权重0.5，domain权重0.5
	combinedVectors := make([]map[string]float64, len(titles))
	for i := 0; i < len(titles); i++ {
		combined := make(map[string]float64)

		// 添加title特征（权重0.5）
		for word, score := range titleVectors[i] {
			combined["title_"+word] = score * 0.5
		}

		// 添加domain特征（权重0.5）
		for word, score := range domainVectors[i] {
			combined["domain_"+word] = score * 0.5
		}

		combinedVectors[i] = combined
	}

	return combinedVectors
}

// extractMainDomain 提取主要域名信息
func (g *TableGenerator) extractMainDomain(domain string) string {
	if domain == "-" || domain == "" {
		return ""
	}

	// 移除常见前缀
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimPrefix(domain, "accounts.")
	domain = strings.TrimPrefix(domain, "login.")
	domain = strings.TrimPrefix(domain, "auth.")
	domain = strings.TrimPrefix(domain, "api.")
	domain = strings.TrimPrefix(domain, "admin.")

	// 提取主域名（去掉子域名）
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		// 保留主要的两部分：如 github.com, google.com
		if len(parts) == 2 {
			return domain
		}
		// 对于三部分的域名，判断是否是知名服务
		if len(parts) == 3 {
			// 常见的二级域名模式
			knownSecondLevel := map[string]bool{
				"com.cn": true,
				"co.uk":  true,
				"com.au": true,
				"co.jp":  true,
			}
			suffix := parts[1] + "." + parts[2]
			if knownSecondLevel[suffix] {
				return domain // 保留完整域名
			}
			return parts[1] + "." + parts[2] // 返回主域名
		}
	}

	return domain
}

// buildTFIDFVectors 构建TF-IDF向量
func (g *TableGenerator) buildTFIDFVectors(titles []string) []map[string]float64 {
	// 文档预处理：分词并标准化
	docs := make([][]string, len(titles))
	allWords := make(map[string]int)

	for i, title := range titles {
		words := g.tokenize(title)
		docs[i] = words
		for _, word := range words {
			allWords[word]++
		}
	}

	// 计算IDF
	idf := make(map[string]float64)
	docCount := float64(len(docs))
	for word, freq := range allWords {
		idf[word] = math.Log(docCount / float64(freq))
	}

	// 计算TF-IDF向量
	vectors := make([]map[string]float64, len(docs))
	for i, doc := range docs {
		vector := make(map[string]float64)
		wordCount := make(map[string]int)

		// 计算词频
		for _, word := range doc {
			wordCount[word]++
		}

		// 计算TF-IDF
		for word, count := range wordCount {
			tf := float64(count) / float64(len(doc))
			vector[word] = tf * idf[word]
		}

		vectors[i] = vector
	}

	return vectors
}

// tokenize 分词和标准化
func (g *TableGenerator) tokenize(text string) []string {
	// 转换为小写
	text = strings.ToLower(text)

	// 分割单词
	words := []string{}
	currentWord := ""

	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			currentWord += string(r)
		} else {
			if currentWord != "" {
				words = append(words, currentWord)
				currentWord = ""
			}
		}
	}

	if currentWord != "" {
		words = append(words, currentWord)
	}

	// 过滤停用词和短词
	filtered := []string{}
	stopWords := map[string]bool{
		"the": true, "and": true, "or": true, "but": true, "in": true, "on": true, "at": true, "to": true, "for": true, "of": true, "with": true, "by": true,
	}

	for _, word := range words {
		if len(word) > 1 && !stopWords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// calculateSimilarityMatrix 计算相似度矩阵
func (g *TableGenerator) calculateSimilarityMatrix(vectors []map[string]float64) [][]float64 {
	n := len(vectors)
	similarities := make([][]float64, n)
	for i := range similarities {
		similarities[i] = make([]float64, n)
	}

	for i := 0; i < n; i++ {
		for j := i; j < n; j++ {
			sim := g.cosineSimilarity(vectors[i], vectors[j])
			similarities[i][j] = sim
			similarities[j][i] = sim
		}
	}

	return similarities
}

// cosineSimilarity 计算余弦相似度
func (g *TableGenerator) cosineSimilarity(v1, v2 map[string]float64) float64 {
	dotProduct := 0.0
	norm1 := 0.0
	norm2 := 0.0

	// 计算点积和范数
	allWords := make(map[string]bool)
	for word := range v1 {
		allWords[word] = true
	}
	for word := range v2 {
		allWords[word] = true
	}

	for word := range allWords {
		val1 := v1[word]
		val2 := v2[word]

		dotProduct += val1 * val2
		norm1 += val1 * val1
		norm2 += val2 * val2
	}

	if norm1 == 0 || norm2 == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(norm1) * math.Sqrt(norm2))
}

// hierarchicalClustering 层次聚类
func (g *TableGenerator) hierarchicalClustering(results []types.DetectionResult, similarities [][]float64, threshold float64) []Cluster {
	n := len(results)
	clusters := make([]Cluster, n)

	// 初始化：每个结果是一个聚类
	for i := 0; i < n; i++ {
		clusters[i] = Cluster{Results: []types.DetectionResult{results[i]}}
	}

	// 合并相似的聚类
	for {
		maxSim := -1.0
		mergeI, mergeJ := -1, -1

		// 找到最相似的两个聚类
		for i := 0; i < len(clusters); i++ {
			for j := i + 1; j < len(clusters); j++ {
				sim := g.clusterSimilarity(clusters[i], clusters[j], similarities, results)
				if sim > maxSim {
					maxSim = sim
					mergeI, mergeJ = i, j
				}
			}
		}

		// 如果最大相似度低于阈值，停止合并
		if maxSim < threshold {
			break
		}

		// 合并聚类
		clusters[mergeI].Results = append(clusters[mergeI].Results, clusters[mergeJ].Results...)
		clusters = append(clusters[:mergeJ], clusters[mergeJ+1:]...)
	}

	return clusters
}

// clusterSimilarity 计算两个聚类的相似度
func (g *TableGenerator) clusterSimilarity(c1, c2 Cluster, similarities [][]float64, allResults []types.DetectionResult) float64 {
	// 使用平均链接法
	totalSim := 0.0
	count := 0

	for _, r1 := range c1.Results {
		for _, r2 := range c2.Results {
			// 找到结果在原数组中的索引
			i1, i2 := -1, -1
			for idx, r := range allResults {
				if r.CredentialID == r1.CredentialID {
					i1 = idx
				}
				if r.CredentialID == r2.CredentialID {
					i2 = idx
				}
			}

			if i1 != -1 && i2 != -1 {
				totalSim += similarities[i1][i2]
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}

	return totalSim / float64(count)
}

// mergeClusters 合并聚类以达到目标数量
func (g *TableGenerator) mergeClusters(clusters []Cluster, similarities [][]float64, targetCount int) []Cluster {
	// 简单实现：如果聚类太多，按大小合并小聚类
	if len(clusters) <= targetCount {
		return clusters
	}

	// 按聚类大小排序
	sort.Slice(clusters, func(i, j int) bool {
		return len(clusters[i].Results) > len(clusters[j].Results)
	})

	// 保留前targetCount个最大的聚类
	if len(clusters) > targetCount {
		// 将小聚类合并到最后一个大聚类中
		for i := targetCount; i < len(clusters); i++ {
			clusters[targetCount-1].Results = append(clusters[targetCount-1].Results, clusters[i].Results...)
		}
		clusters = clusters[:targetCount]
	}

	return clusters
}

// generateClusterName 生成聚类名称
func (g *TableGenerator) generateClusterName(results []types.DetectionResult) string {
	if len(results) == 0 {
		return "Empty Group"
	}

	if len(results) == 1 {
		return g.shortenTitle(results[0].Title)
	}

	// 先检查是否有共同的域名
	commonDomain := g.findCommonDomain(results)
	if commonDomain != "" {
		// 有共同域名，基于域名生成名称
		return g.generateDomainBasedName(commonDomain, results)
	}

	// 没有共同域名，基于title的共同关键词生成名称
	return g.generateTitleBasedName(results)
}

// generateTitleBasedName 基于title生成聚类名称
func (g *TableGenerator) generateTitleBasedName(results []types.DetectionResult) string {
	// 提取所有title中的关键词
	wordFreq := make(map[string]int)
	totalWords := 0

	for _, result := range results {
		words := g.tokenize(result.Title)
		for _, word := range words {
			if len(word) > 2 { // 过滤掉太短的词
				wordFreq[word]++
				totalWords++
			}
		}
	}

	// 找到出现频率高且有意义的词
	var candidateWords []struct {
		word  string
		freq  int
		score float64
	}

	for word, freq := range wordFreq {
		// 计算相对频率和绝对频率的综合得分
		relativeFreq := float64(freq) / float64(len(results))
		score := float64(freq) * relativeFreq

		// 只考虑在至少40%的结果中出现的词
		if relativeFreq >= 0.4 && freq >= 2 {
			candidateWords = append(candidateWords, struct {
				word  string
				freq  int
				score float64
			}{word, freq, score})
		}
	}

	// 按得分排序
	sort.Slice(candidateWords, func(i, j int) bool {
		return candidateWords[i].score > candidateWords[j].score
	})

	// 生成聚类名称
	if len(candidateWords) > 0 {
		topWord := candidateWords[0].word
		// 首字母大写
		if len(topWord) > 0 {
			topWord = strings.ToUpper(topWord[:1]) + topWord[1:]
		}

		// 如果有第二个高频词，组合使用
		if len(candidateWords) > 1 && candidateWords[1].score >= candidateWords[0].score*0.7 {
			secondWord := candidateWords[1].word
			if len(secondWord) > 0 {
				secondWord = strings.ToUpper(secondWord[:1]) + secondWord[1:]
			}
			return topWord + " & " + secondWord + " Services"
		}

		return topWord + " Services"
	}

	// 如果没有找到共同关键词，尝试从域名中提取
	domains := make(map[string]int)
	for _, result := range results {
		domain := g.extractMainDomain(g.extractDomain(result.Metadata))
		if domain != "" && domain != "unknown" {
			// 提取域名的主要部分作为关键词
			parts := strings.Split(domain, ".")
			if len(parts) > 0 {
				mainPart := parts[0]
				domains[mainPart]++
			}
		}
	}

	// 找到最频繁的域名关键词
	maxCount := 0
	dominantDomain := ""
	for domain, count := range domains {
		if count > maxCount {
			maxCount = count
			dominantDomain = domain
		}
	}

	if dominantDomain != "" && maxCount >= len(results)/3 {
		dominantDomain = strings.ToUpper(dominantDomain[:1]) + dominantDomain[1:]
		return dominantDomain + " Related Services"
	}

	// 最后的回退：使用第一个结果的简短标题
	return g.shortenTitle(results[0].Title) + " & Others"
}

// generateDomainBasedName 基于域名生成聚类名称
func (g *TableGenerator) generateDomainBasedName(domain string, results []types.DetectionResult) string {
	// 域名到服务名称的映射
	domainToService := map[string]string{
		"aws.amazon.com":               "AWS",
		"amazon.com":                   "Amazon",
		"amazon.cn":                    "Amazon CN",
		"google.com":                   "Google",
		"apple.com":                    "Apple",
		"appleid.apple.com":            "Apple",
		"microsoft.com":                "Microsoft",
		"github.com":                   "GitHub",
		"gitlab.com":                   "GitLab",
		"aliyun.com":                   "Aliyun",
		"alibabacloud.com":             "Alibaba Cloud",
		"tencent.com":                  "Tencent",
		"qq.com":                       "QQ/WeChat",
		"163.com":                      "NetEase",
		"126.com":                      "NetEase",
		"baidu.com":                    "Baidu",
		"weibo.com":                    "Weibo",
		"twitter.com":                  "Twitter",
		"x.com":                        "X/Twitter",
		"facebook.com":                 "Facebook",
		"instagram.com":                "Instagram",
		"linkedin.com":                 "LinkedIn",
		"sony.com":                     "Sony",
		"sonyentertainmentnetwork.com": "Sony PlayStation",
		"steam.com":                    "Steam",
		"store.steampowered.com":       "Steam",
		"epicgames.com":                "Epic Games",
		"adobe.com":                    "Adobe",
		"cloudflare.com":               "Cloudflare",
		"digitalocean.com":             "DigitalOcean",
		"vultr.com":                    "Vultr",
		"linode.com":                   "Linode",
		"paypal.com":                   "PayPal",
		"stripe.com":                   "Stripe",
		"jetbrains.com":                "JetBrains",
		"stackoverflow.com":            "Stack Overflow",
		"reddit.com":                   "Reddit",
		"discord.com":                  "Discord",
		"slack.com":                    "Slack",
		"zoom.us":                      "Zoom",
		"dropbox.com":                  "Dropbox",
		"box.com":                      "Box",
		"notion.so":                    "Notion",
		"spotify.com":                  "Spotify",
		"netflix.com":                  "Netflix",
		"twitch.tv":                    "Twitch",
		"youtube.com":                  "YouTube",
	}

	// 查找已知服务名称
	if serviceName, exists := domainToService[domain]; exists {
		return serviceName + " Services"
	}

	// 尝试从域名提取服务名称
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		mainPart := parts[0]
		// 首字母大写
		if len(mainPart) > 0 {
			mainPart = strings.ToUpper(mainPart[:1]) + mainPart[1:]
			return mainPart + " Services"
		}
	}

	return "Related Services"
}

// findCommonDomain 找到结果中的共同域名
func (g *TableGenerator) findCommonDomain(results []types.DetectionResult) string {
	if len(results) <= 1 {
		return ""
	}

	domainCount := make(map[string]int)
	for _, result := range results {
		domain := g.extractDomain(result.Metadata)
		mainDomain := g.extractMainDomain(domain)
		if mainDomain != "" {
			domainCount[mainDomain]++
		}
	}

	// 如果超过一半的结果有相同的主域名，认为是共同域名
	threshold := len(results) / 2
	if len(results) >= 3 {
		threshold = len(results) * 2 / 3 // 至少2/3相同
	}

	for domain, count := range domainCount {
		if count >= threshold {
			return domain
		}
	}

	return ""
}

// shortenTitle 缩短标题
func (g *TableGenerator) shortenTitle(title string) string {
	words := strings.Fields(title)
	if len(words) <= 2 {
		return title
	}
	return strings.Join(words[:2], " ")
}

// extractDomain 从元数据中提取域名
func (g *TableGenerator) extractDomain(metadata map[string]interface{}) string {
	if domain, exists := metadata["domain"]; exists {
		if domainStr, ok := domain.(string); ok {
			return domainStr
		}
	}
	return "-"
}

// isStopWord 检查是否为停用词
func (g *TableGenerator) isStopWord(word string) bool {
	stopWords := map[string]bool{
		"the": true, "and": true, "or": true, "but": true, "in": true, "on": true, "at": true, "to": true, "for": true, "of": true, "with": true, "by": true,
		"com": true, "net": true, "org": true, "www": true, "http": true, "https": true,
		"login": true, "account": true, "user": true, "password": true, "sign": true, "auth": true,
		"是": true, "的": true, "了": true, "在": true, "我": true, "有": true, "和": true, "就": true, "不": true, "人": true, "都": true, "一": true, "一个": true,
	}
	return stopWords[strings.ToLower(word)]
}
