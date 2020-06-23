#include <iostream>
#include <Eigen/Sparse>
#include <unordered_map>
#include <vector>
#include <string>
#include <set>

using namespace std;
using namespace Eigen;

struct Slot {
	int id;
	set<string> flows;
    int exp_val;
    int actual_val;
};

struct Switch {
	unordered_map<int, Slot> slots;	

    void update_switch(int slot_id, string flowkey, int val) {
        Slot s = slots[slot_id];
        s.flows.insert(flowkey);
    }
};

struct Flow {
	string flowkey;
    vector<int> switches;
    vector<int> slot_1;
    vector<int> slot_2;
    set<string> slots;
    int loss_val;
};

unordered_map<string, int> src_info;
unordered_map<string, int> dst_info;
// unordered_map<int, Switch> switch_info;

int host_ids[] = {3, 10};
int switch_ids[] = {1, 3};
int n_host = 2;
int n_switch = 2;

void work(char* dir) {
    char filename[100];
    char line[100];
    FILE* fp = NULL;

    // read stat in source hosts
    for (int i=0; i<n_host; i++) {
        sprintf(filename, "%s/src_%d.txt", dir, host_ids[i]);
        fp = fopen(filename, "r");
        if (fp == NULL) {
            continue;
        }
        while (fgets(line, 100, fp) != NULL) {
            string s = line;
            int pos = s.find(";");
            string flowkey = s.substr(0, pos);
            int size = stoi(s.substr(pos+2));
            src_info[flowkey] = size;
        }
        fclose(fp);
    }

    // read stat in end hosts
    for (int i=0; i<n_host; i++) {
        for (int j=i+1; i<n_host; i++) {
            sprintf(filename, "%s/dst_%d_%d.txt", dir, host_ids[i], host_ids[j]);
            fp = fopen(filename, "r");
            if (fp == NULL) {
                continue;
            }
            while (fgets(line, 100, fp) != NULL) {
                string s = line;
                int pos = s.find(" ");
                int index = stoi(s.substr(0, pos));
                char key[100];
                sprintf(key, "%d_%d_%d", host_ids[i], host_ids[j], index);
                int size = stoi(s.substr(pos+1));
                dst_info[key] = size;
            }
            fclose(fp);
        }
    }


    vector<Flow> lossy_flows;
    unordered_map<int, unordered_map<int, int>> switch_exp_cnt;

    // read flow path
    sprintf(filename, "%s/path.txt", dir);
    fp = fopen(filename, "r");
    while (fgets(line, 100, fp) != NULL) {
        string s = line;
        int pos = s.find(";");

        string flowkey = s.substr(0, pos);
        
        int src_val = 0;
        int src_host = -1;
        vector<string> switch_list;

        char path[100];
        sprintf(path, "%s", s.c_str()+pos+2);
        char* tok = strtok(path, " ");
        while (tok != NULL) {
            if (tok[0] == 'h') {
                string sh = tok;
                pos = sh.find(":");
                int host_index = stoi(sh.substr(1, pos));
                int slot = stoi(sh.substr(pos+1));

                if (src_host < 0) {
                    src_host = host_index;
                    src_val = src_info[flowkey];
                }
                else {
                    char key[100];
                    sprintf(key, "%d_%d_%d", src_host, host_index, slot);
                    int dst_val = dst_info[key];
                    if (dst_val < src_val) {
                        Flow f;
                        f.flowkey = flowkey;
                        f.loss_val = src_val - dst_val;
                        for (size_t i=0; i<switch_list.size(); i++) {
                            string ss = switch_list[i];
                            int pos1 = ss.find(":");
                            int pos2 = ss.find(",");
                            int switch_index = stoi(ss.substr(1, pos1));
                            int slot1 = stoi(ss.substr(pos1+1, pos2));
                            int slot2 = stoi(ss.substr(pos2+1));
                            f.switches.push_back(switch_index);
                            f.slot_1.push_back(slot1);
                            f.slot_2.push_back(slot2);
                            f.slots.insert(to_string(switch_index) + "_" + to_string(slot1));
                            f.slots.insert(to_string(switch_index) + "_" + to_string(slot2));
                        }
                        lossy_flows.push_back(f);
                    }
                }
            }
            else {
                string ss = tok;
                int pos1 = ss.find(":");
                int pos2 = ss.find(",");
                int switch_index = stoi(ss.substr(1, pos1));
                int slot1 = stoi(ss.substr(pos1+1, pos2));
                int slot2 = stoi(ss.substr(pos2+1));
                switch_exp_cnt[switch_index][slot1] += src_val;
                switch_exp_cnt[switch_index][slot2] += src_val;

                switch_list.push_back(ss);
            }
            tok = strtok(NULL, " ");
        }
    }
    fclose(fp);

    // read stat in switches
    unordered_map<int, unordered_map<int, int>> lossy_switches;

    int n_slot = 0; 
    for (int i=0; i<n_switch; i++) {
        sprintf(filename, "%s/s%d.txt", dir, switch_ids[i]);
        fp = fopen(filename, "r");
        if (fp == NULL) {
            continue;
        }
        while (fgets(line, 100, fp) != NULL) {
            string s = line;
            int pos = s.find(" ");
            int slot = stoi(s.substr(0, pos));
            int val = stoi(s.substr(pos+1));

            int exp_val = switch_exp_cnt[switch_ids[i]][slot];
            if (val < exp_val) {
                lossy_switches[switch_ids[i]][slot] = exp_val - val;
                n_slot += 1;
            }
        }
        fclose(fp);
    }

    set<string> remove_slot;
    set<string> remove_flow;
	// for (auto sw : lossy_switches) {
    //     int switch_id = sw.first;
    //     for (auto slot : sw.second) {
    //         int slot_id = slot.first;
    //         int val = slot.second;
    //         string slot_key = to_string(switch_id) + "_" + to_string(slot_id);

    //         int slot_flow = 0;
    //         int flow_index = -1;
    //         for (int i=0; i<lossy_flows.size(); i++) {
    //             if (lossy_flows[i].slots.find(slot_key) != lossy_flows[i].slots.end()) {
    //                 slot_flow += 1;
    //                 flow_index = i;
    //                 if (slot_flow > 1) {
    //                     break;
    //                 }
    //             }
    //         }

    //         if (slot_flow == 1) {
    //             printf("Switch %d (Slot %d) drops %d packets of flow %s\n", switch_id, slot_id,
    //                     lossy_flows[flow_index].loss_val, lossy_flows[flow_index].flowkey.c_str());
    //             remove_slot.insert(slot_key);
    //             remove_flow.insert(lossy_flows[flow_index].flowkey);
    //         }
    //     }
    // }
    

    for (size_t i=0; i<lossy_flows.size(); i++) {

        int n_switch = 0;
        int switch_index = -1;
        int slot_index_1 = -1;
        int slot_index_2 = -1;
        for (size_t j=0; j<lossy_flows[i].switches.size(); j++) {
            int switch_id = lossy_flows[i].switches[j];
            int slot_1 = lossy_flows[i].slot_1[j];
            int slot_2 = lossy_flows[i].slot_2[j];
            if (lossy_switches.find(switch_id) != lossy_switches.end() and lossy_switches[switch_id].find(slot_1) != lossy_switches[switch_id].end()) {
                n_switch += 1;
                switch_index = switch_id;
                slot_index_1 = slot_1;
                slot_index_2 = slot_2;
                if (n_switch > 1) {
                    break;
                }
            }
        }

        if (n_switch == 1) {
            printf("Switch %d (Slot %d) drops %d packets of flow %s\n", switch_index, slot_index_1,
                    lossy_flows[i].loss_val, lossy_flows[i].flowkey.c_str());
            printf("Switch %d (Slot %d) drops %d packets of flow %s\n", switch_index, slot_index_2,
                    lossy_flows[i].loss_val, lossy_flows[i].flowkey.c_str());

            string slot_key = to_string(switch_index) + "_" + to_string(slot_index_1);
            remove_slot.insert(slot_key);
            slot_key = to_string(switch_index) + "_" + to_string(slot_index_2);
            remove_slot.insert(slot_key);
            remove_flow.insert(lossy_flows[i].flowkey);
        }
    }

    for (vector<Flow>::iterator it = lossy_flows.begin(); it != lossy_flows.end(); ) {
        if (remove_flow.find(it->flowkey) != remove_flow.end()) {
            lossy_flows.erase(it);
        }
        else {
            ++it;
        }
    }

    for (unordered_map<int, unordered_map<int, int>>::iterator it = lossy_switches.begin(); it != lossy_switches.end(); ) {
        int switch_id = it->first;
        for (unordered_map<int, int>::iterator it1 = it->second.begin(); it1 != it->second.end(); ) {
            int slot_id = it1->first;
            string slot_key = to_string(switch_id) + "_" + to_string(slot_id);
            if (remove_slot.find(slot_key) != remove_slot.end()) {
                it->second.erase(it1++);
            }
            else {
                ++it1;
            }
        }

        if (it->second.size() == 0) {
            lossy_switches.erase(it++);
        }
        else {
            ++it;
        }
    }

    if (lossy_flows.size() > 0 and lossy_switches.size() > 0) {
        // Construct A and b
        vector<Triplet<double>> triplets;
        VectorXd b(lossy_flows.size() + n_slot);

        int n_switch = 0;
        int n_line = 0;
	    for (auto sw : lossy_switches) {
            int switch_id = sw.first;
            for (auto slot : sw.second) {
                int slot_id = slot.first;
                int val = slot.second;

                string slot_key = to_string(switch_id) + "_" + to_string(slot_id);
                for (size_t i=0; i<lossy_flows.size(); i++) {
                    if (lossy_flows[i].slots.find(slot_key) != lossy_flows[i].slots.end()) {
                        int col = n_switch * lossy_flows.size() + i;
                        triplets.push_back(Triplet<double>(n_line, col, 1));
                        b[n_line] = val;
                    }
                }


                n_line += 1;
            }

            n_switch += 1;
        } 

        for (size_t i=0; i<lossy_flows.size(); i++) {
            for (size_t j=0; j<lossy_switches.size(); j++) {
                triplets.push_back(Triplet<double>(n_line+i, j*lossy_flows.size()+i, 1));
                b[n_line] = lossy_flows[i].loss_val;
            }
        }

        SparseMatrix<double> A(n_line+lossy_flows.size(), lossy_flows.size()*n_switch);
        A.setFromTriplets(triplets.begin(), triplets.end());
        cout << A << endl;
        cout << b << endl;

	    A.makeCompressed();
	    SparseQR<SparseMatrix<double>, COLAMDOrdering<int>> solver;
	    solver.compute(A);
	    VectorXd x = solver.solve(b);
	    for (int i = 0; i < x.rows(); i++){
	    	cout << "x" << i << " = " << x[i] << endl;
	    }
    }

}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s [data dir]\n", argv[0]);
        return 0;
    }

    work(argv[1]);

	return 0;
}
