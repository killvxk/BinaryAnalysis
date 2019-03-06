#ifndef SYNTHESIZE_GRAMMAR_H
#define SYNTHESIZE_GRAMMAR_H

#include <vector>
#include <list>
#include <string>

class NonTerminal {
public:
    NonTerminal(const std::wstring& nonTerminal) : m_nonTerminal(nonTerminal){ }
private:
    std::wstring m_nonTerminal;
};

class Terminal {
public:
    Terminal(char repr) : m_repr(repr) { }

private:
    char m_repr;
};

class Production {
public:
    Production() {

    }
private:
};

class Variable {
public:
    Variable(std::wstring name, const int size)
    : m_name(std::move(name)), m_size(size) { }
private:
    std::wstring m_name;
    int m_size;
};

class Grammar {
public:
    using NonTerminalIter = std::vector<NonTerminal>::iterator;
    using ConstNonTerminalIter = std::vector<NonTerminal>::const_iterator;

    explicit Grammar(int bitsize);

    void addProduction(Production p);
    void addTerminal(Terminal t);
    void addNonTerminal(NonTerminal nt);

    NonTerminalIter getNonTerminals() { return m_nonTerminals.begin(); }
    ConstNonTerminalIter getNonTerminals() const { return m_nonTerminals.cbegin(); }

private:
    std::vector<NonTerminal> m_nonTerminals;
    std::vector<Terminal> m_terminals;
    std::list<Production> m_productions;
    std::vector<int> m_bit_sizes;
};


#endif //SYNTHESIZE_GRAMMAR_H
