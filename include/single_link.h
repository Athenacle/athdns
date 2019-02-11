
#ifndef SINGLE_LINK_H
#define SINGLE_LINK_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>

#include <algorithm>
#include <cassert>
#include <functional>
#include <iterator>
#include <memory>
#include <utility>

namespace utils
{
    template <class T>
    class single_link_node;

    template <class T>
    class single_link;

    template <class T>
    class single_link_input_iterator;

    namespace allocator
    {
        template <class T>
        class allocator
        {
            using value_type = T;
            using pointer    = value_type *;
            using size_type  = size_t;

        public:
            static pointer allocate(size_type count)
            {
                return reinterpret_cast<T *>(malloc(sizeof(T) * count));
            }

            template <class... Args>
            static pointer construct(T *p, Args &&... args)
            {
                return new (p) T(std::forward<Args>(args)...);
            }

            static pointer construct(T *p)
            {
                return new (p) T;
            }

            static void destroy(T *p)
            {
                p->~T();
            }

            static void deallocate(T *p)
            {
                free(p);
            }
        };

    }  // namespace allocator

    template <class T>
    class single_link_node
    {
        using value_type         = T;
        using value_type_pointer = T *;
        using node_type          = single_link_node<value_type>;
        using node_type_ptr      = node_type *;

        using alloc = allocator::allocator<T>;

        friend class single_link_input_iterator<T>;

        using forward_iterator = single_link_input_iterator<T>;

        using const_reference = const T &;
        using reference       = T &;

    private:
        value_type_pointer __value;
        node_type_ptr __next;

    public:
        const_reference value() const
        {
            return *__value;
        }

        reference value()
        {
            return *__value;
        }

        const_reference operator*() const
        {
            return *__value;
        }

        reference operator*()
        {
            return *__value;
        }

        value_type_pointer address() const
        {
            return __value;
        }

        single_link_node()
        {
            __value = nullptr;
            __next  = nullptr;
        }


        template <class... Args>
        single_link_node(Args &&... args)
        {
            __value = alloc::allocate(1);
            alloc::construct(__value, std::forward<Args>(args)...);
            __next = nullptr;
        }

        ~single_link_node()
        {
            alloc::destroy(__value);
            alloc::deallocate(__value);
        }

        node_type_ptr get_next() const
        {
            return __next;
        }

        void set_next(node_type_ptr n)
        {
            __next = n;
        }
    };

    template <class T>
    class single_link_input_iterator
        : public std::iterator<std::input_iterator_tag, single_link_node<T>>
    {
        using node_type = single_link_node<T>;

    public:
        single_link_input_iterator(node_type *p)
        {
            __pointer = p;
        }

        single_link_input_iterator &operator=(const single_link_input_iterator &iter)
        {
            __pointer = iter._ptr;
        }

        void next()
        {
            this->__pointer = __pointer->get_next();
        }


        bool operator!=(const single_link_input_iterator &iter)
        {
            return __pointer != iter.__pointer;
        }
        bool operator==(const node_type *p) const
        {
            return __pointer == p;
        }

        bool operator==(const single_link_input_iterator &iter) const
        {
            return __pointer == iter.__pointer;
        }

        single_link_input_iterator &operator++()
        {
            __pointer = __pointer->get_next();
            return *this;
        }

        single_link_input_iterator operator++(int)
        {
            single_link_input_iterator tmp = *this;

            __pointer = __pointer->get_next();
            return tmp;
        }

        const T &operator*() const
        {
            return __pointer->value();
        }

        T *address()
        {
            return __pointer->address();
        }

        T *operator->()
        {
            return __pointer->address();
        }

    private:
        node_type *__pointer;
    };

    template <class T>
    class single_link
    {
    public:
        using value_type           = T;
        using node_type            = single_link_node<T>;
        using node_type_pointer    = node_type *;
        using value_type_pointer   = value_type *;
        using value_type_reference = value_type &;

        using const_value_reference = const value_type &;


        using forward_iterator = single_link_input_iterator<T>;

    private:
        using alloc = allocator::allocator<node_type>;

        node_type_pointer head_node;
        node_type_pointer end_node;

        pthread_spinlock_t lock;

        int saved;

        alloc allocator;

    public:
        forward_iterator begin() const
        {
            return forward_iterator(head_node);
        }

        void remove(const forward_iterator &iter)
        {
            if (unlikely(iter == head_node)) {
                pthread_spin_lock(&lock);
                if (iter == end_node) {
                    alloc::destroy(head_node);
                    alloc::deallocate(head_node);
                    head_node = end_node = nullptr;
                } else {
                    //first, but not last node in single link
                    auto head = head_node;
                    head_node = head->get_next();
                    alloc::destroy(head);
                    alloc::deallocate(head);
                }
            } else {
                node_type_pointer begin = head_node;
                node_type_pointer next  = nullptr;

                do {
                    next = begin->get_next();
                    if (iter == next) {
                        break;
                    }
                    begin = next;
                } while (true);
                assert(iter == next);
                assert(!(iter == begin));
                assert(iter == begin->get_next());
                alloc::destroy(next);
                alloc::deallocate(next);

                pthread_spin_lock(&lock);
                begin->set_next(next);
            }
            saved--;
            pthread_spin_unlock(&lock);
        }


        forward_iterator end() const
        {
            return forward_iterator(nullptr);
        }

        ~single_link()
        {
            if (likely(head_node != nullptr)) {
                for (auto p = head_node; p != end_node;) {
                    auto np = p->get_next();
                    alloc::destroy(p);
                    alloc::deallocate(p);
                    p = np;
                }
                alloc::destroy(end_node);
                alloc::deallocate(end_node);
            }
            pthread_spin_destroy(&lock);
        }

        single_link()
        {
            pthread_spin_init(&lock, PTHREAD_PROCESS_PRIVATE);
            head_node = end_node = nullptr;
            saved                = 0;
        }

        template <class... Args>
        value_type_pointer append(Args &&... args)
        {
            single_link_node<T> *ins = alloc::allocate(1);
            alloc::construct(ins, std::forward<Args>(args)...);
            pthread_spin_lock(&lock);
            if (unlikely(head_node == nullptr)) {
                head_node = end_node = ins;
            } else {
                end_node->set_next(ins);
                end_node = ins;
            }
            saved++;
            pthread_spin_unlock(&lock);
            return ins->address();
        }

        int get_saved() const
        {
            return saved;
        }
    };

}  // namespace utils

#endif
