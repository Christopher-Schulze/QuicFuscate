#pragma once

#include <cstddef>
#include <iterator>
#include <type_traits>
#include <array>
#include <stdexcept>

namespace quicsand {

/**
 * memory_span - Eine leichtgewichtige std::span Alternative für C++17
 * 
 * Diese Klasse bietet eine nicht-besitzende Ansicht auf zusammenhängende Sequenzen 
 * von Objekten und reduziert unnötige Kopien von Daten. Die Implementierung 
 * orientiert sich an std::span aus C++20, ist aber kompatibel mit C++17.
 */
template<typename T>
class memory_span {
public:
    // Typdefinitionen
    using element_type = T;
    using value_type = std::remove_cv_t<T>;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using iterator = pointer;
    using const_iterator = const_pointer;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    // Statische Konstanten
    static constexpr size_type npos = static_cast<size_type>(-1);

    // Konstruktoren
    constexpr memory_span() noexcept : data_(nullptr), size_(0) {}

    constexpr memory_span(pointer ptr, size_type size) noexcept : data_(ptr), size_(size) {}

    constexpr memory_span(pointer first, pointer last) noexcept : 
        data_(first), size_(static_cast<size_type>(last - first)) {}

    // Konstruktor für Array-Referenzen
    template<size_t N>
    constexpr memory_span(element_type (&arr)[N]) noexcept : data_(arr), size_(N) {}

    // Konstruktor für std::array
    template<size_t N>
    constexpr memory_span(std::array<value_type, N>& arr) noexcept : 
        data_(arr.data()), size_(N) {}

    template<size_t N>
    constexpr memory_span(const std::array<value_type, N>& arr) noexcept : 
        data_(arr.data()), size_(N) {}

    // Konstruktor für Container mit data() und size() Methoden
    template<typename Container>
    constexpr memory_span(Container& cont) noexcept : 
        data_(cont.data()), size_(cont.size()) {}

    template<typename Container>
    constexpr memory_span(const Container& cont) noexcept : 
        data_(cont.data()), size_(cont.size()) {}

    // Zugriffsmethoden
    constexpr reference operator[](size_type idx) const noexcept {
        return data_[idx];
    }

    constexpr reference at(size_type idx) const {
        if (idx >= size_) {
            throw std::out_of_range("memory_span index out of range");
        }
        return data_[idx];
    }

    constexpr reference front() const noexcept {
        return data_[0];
    }

    constexpr reference back() const noexcept {
        return data_[size_ - 1];
    }

    constexpr pointer data() const noexcept {
        return data_;
    }

    // Iteratoren
    constexpr iterator begin() const noexcept {
        return data_;
    }

    constexpr iterator end() const noexcept {
        return data_ + size_;
    }

    constexpr const_iterator cbegin() const noexcept {
        return data_;
    }

    constexpr const_iterator cend() const noexcept {
        return data_ + size_;
    }

    constexpr reverse_iterator rbegin() const noexcept {
        return reverse_iterator(end());
    }

    constexpr reverse_iterator rend() const noexcept {
        return reverse_iterator(begin());
    }

    constexpr const_reverse_iterator crbegin() const noexcept {
        return const_reverse_iterator(cend());
    }

    constexpr const_reverse_iterator crend() const noexcept {
        return const_reverse_iterator(cbegin());
    }

    // Kapazität
    constexpr bool empty() const noexcept {
        return size_ == 0;
    }

    constexpr size_type size() const noexcept {
        return size_;
    }

    constexpr size_type size_bytes() const noexcept {
        return size_ * sizeof(element_type);
    }

    // Unteransichten
    constexpr memory_span<T> first(size_type count) const noexcept {
        count = (count < size_) ? count : size_;
        return memory_span<T>(data_, count);
    }

    constexpr memory_span<T> last(size_type count) const noexcept {
        count = (count < size_) ? count : size_;
        return memory_span<T>(data_ + (size_ - count), count);
    }

    constexpr memory_span<T> subspan(size_type offset, size_type count = npos) const noexcept {
        offset = (offset < size_) ? offset : size_;
        count = (count == npos) ? (size_ - offset) : count;
        count = ((offset + count) < size_) ? count : (size_ - offset);
        return memory_span<T>(data_ + offset, count);
    }

private:
    pointer data_;
    size_type size_;
};

// Deduktionsanleitungen (C++17 deduction guides)
template<typename T, size_t N>
memory_span(T (&)[N]) -> memory_span<T>;

template<typename T, size_t N>
memory_span(std::array<T, N>&) -> memory_span<T>;

template<typename T, size_t N>
memory_span(const std::array<T, N>&) -> memory_span<const T>;

template<typename Container>
memory_span(Container&) -> memory_span<typename Container::value_type>;

template<typename Container>
memory_span(const Container&) -> memory_span<const typename Container::value_type>;

// Hilfsfunktion zum Erstellen eines memory_span aus Rohzeiger und Größe
template<typename T>
constexpr memory_span<T> make_span(T* ptr, size_t size) noexcept {
    return memory_span<T>(ptr, size);
}

// Hilfsfunktion zum Erstellen eines memory_span aus einem Container
template<typename Container>
constexpr auto make_span(Container& cont) noexcept {
    return memory_span(cont);
}

// Hilfsfunktion zum Erstellen eines memory_span aus Anfangs- und Endzeigern
template<typename T>
constexpr memory_span<T> make_span(T* first, T* last) noexcept {
    return memory_span<T>(first, last);
}

} // namespace quicsand
