package ch.krmpoti.master;

public interface Filter {

    /**
     * Returns the total number of positions inside the filter.
     *
     * @return The size of the filter.
     */
    int size();

    /**
     * Returns the number of hash functions used.
     *
     * @return The number of hash functions.
     */
    int getHashCount();

    /**
     * Adds a given element to the filter.
     *
     * @param a The object to be added to the filter.
     * @return An array of filter's indexes affected by the added element.
     */
    int[] add(Object a);

    /**
     * Checks whether the given element is possibly in the filter. Due to possibility of false positives only the
     * false cases are considered to be accurate.
     *
     * @param a The object to be checked in the filter.
     * @return True if the filter possibly contains the provided element, false if it definitely does not contain it.
     */
    boolean maybeContains(Object a);

    /**
     * Sets all the bits in the filter to 0.
     *
     */
    void reset();

}
