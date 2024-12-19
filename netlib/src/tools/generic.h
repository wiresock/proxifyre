#pragma once

namespace tools::generic
{
    // ********************************************************************************
    /// <summary>
    /// erase_if template for associative containers
    /// </summary>
    // ********************************************************************************
    template <typename ContainerT, class FwdIt, class Pr>
    void erase_if(ContainerT& items, FwdIt it, FwdIt last, Pr predicate)
    {
        while (it != last)
        {
            if (predicate(*it)) it = items.erase(it);
            else ++it;
        }
    }
}
