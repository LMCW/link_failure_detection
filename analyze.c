#include "analyze.h"
#include "stdio.h"

void link_statistic(char const*prefix_file, char const*as_rel_file, char const*rib_file, char const*out_file){
	trie_node *rib_root = load_rib(as_rel_file, rib_file);
	int set_size = pfx_file_size(prefix_file);
	prefix *pfx_set = pfx_set_from_file(prefix_file, set_size);
	int i, x;
	FILE *fout = fopen(out_file,"w");
	for (i = 0;i < set_size;++i){
		trie_node *tmp_node = trie_search(rib_root, ip_key_l(pfx_set[i].ip));
		fprintf(fout, "%lu.%lu.%lu.%lu/%d\t", pfx_set[i].ip >> 24,
			(pfx_set[i].ip >> 16) & 0xff,
			(pfx_set[i].ip >> 8) & 0xff,
			pfx_set[i].ip & 0xff,
			pfx_set[i].slash);
		for (x = 0;x < 15;++x){
			if (tmp_node->path.nodes[x] != 0)
				fprintf(fout,"%d ", tmp_node->path.nodes[x]);
		}
		fprintf(fout, "\n");
	}
	fclose(fout);
}