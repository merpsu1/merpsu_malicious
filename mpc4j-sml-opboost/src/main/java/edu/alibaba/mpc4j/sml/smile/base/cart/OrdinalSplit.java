/*******************************************************************************
 * Original Work: Copyright (c) 2010-2020 Haifeng Li. All rights reserved.
 * Modified Work: Copyright (c) 2021-2022 Weiran Liu.
 *
 * Smile is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Smile is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Smile.  If not, see <https://www.gnu.org/licenses/>.
 ******************************************************************************/

package edu.alibaba.mpc4j.sml.smile.base.cart;

import java.util.function.IntPredicate;

/**
 * The data about of a potential split for a leaf node.
 *
 * @author Haifeng Li
 */
public class OrdinalSplit extends Split {
    /**
     * The split value.
     */
    final double value;
    /**
     * The left value for splitting.
     */
    final double leftValue;
    /**
     * The right value for splitting.
     */
    final double rightValue;
    /**
     * The lambda returns true if the sample passes the test on the split feature.
     */
    final IntPredicate predicate;

    /**
     * Constructor.
     */
    public OrdinalSplit(LeafNode leaf, int feature, double value, double leftValue, double rightValue,
                        double score, int lo, int hi, int trueCount, int falseCount, IntPredicate predicate) {
        super(leaf, feature, score, lo, hi, trueCount, falseCount);
        this.value = value;
        this.leftValue = leftValue;
        this.rightValue = rightValue;
        this.predicate = predicate;
    }

    @Override
    public OrdinalNode toNode(Node trueChild, Node falseChild) {
        return new OrdinalNode(feature, value, leftValue, rightValue, score, leaf.deviance(), trueChild, falseChild);
    }

    @Override
    public IntPredicate predicate() {
        return predicate;
    }
}
