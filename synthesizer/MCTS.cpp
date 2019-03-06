#include "MCTS.h"

#include <deque>

using namespace std;

Node *MCTS::select(Node *p) {

    return nullptr;
}

Node *MCTS::expand(Node *p) {
    return nullptr;
}

void MCTS::execute(Node *root_node) {

}

void MCTS::backpropagation(Node *p) {

}

void MCTS::play_simulated_game(Node *root_node) {
    Node* curr = root_node;
    Node* last_node;

    while (curr != nullptr) {
        last_node = curr;
        curr = select(curr);
    }

    last_node = expand(last_node);

    play_simulated_game(last_node);

    curr = last_node;

    while (curr != nullptr) {
        backpropagation(curr, R);
        curr = curr->get_parent();
    }

}
