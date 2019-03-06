#ifndef SYNTHESIZE_MCTS_H
#define SYNTHESIZE_MCTS_H

#include <vector>
#include <list>

class Node {
public:
    std::vector<Node*>& get_childs() { return m_childs; }
    Node *get_parent() const { return m_parent; }

    void inc_visited() { m_visited++; }

private:
    double m_score;
    int m_visited;
    Node *m_parent;
    std::list<Node*> m_childs;
};

class MCTS {
public:
    MCTS() { }


    Node *select(Node* p);

    Node *expand(Node* p);

    void backpropagation(Node *p);

    void execute(Node *root_node);

    void play_simulated_game(Node *root_node);

private:
    bool m_hasTime;
};

#endif //SYNTHESIZE_MCTS_H
