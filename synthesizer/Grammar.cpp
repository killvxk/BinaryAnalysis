#include "Grammar.h"
#include <string>

using namespace std;

static std::vector<int> generate_sizes(int bitsize) {

}

void Grammar::addProduction(Production p) {

}

void Grammar::addTerminal(Terminal t) {

}

void Grammar::addNonTerminal(NonTerminal nt) {

}

Grammar::Grammar(int bitsize) {
    m_bit_sizes = generate_sizes(bitsize);

    for (auto i : m_bit_sizes) {
        m_nonTerminals.emplace_back("u" + );
    }
}

