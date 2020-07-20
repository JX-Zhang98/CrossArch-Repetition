#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import random


class SampleValues:
    """
    the sample values we used

    Attributes:
        sample: the saved values
        sample_example: one example of sample value
    """
    sample_example = [[[954], [803, 7], [855, 407, 756], [895, 461, 890, 850]],
                      [[672], [853, 290], [279, 716, 366], [39, 879, 348, 553]],
                      [[490], [127, 460], [66, 351, 217], [934, 330, 356, 938]],
                      [[324], [345, 499], [229, 110, 793], [463, 394, 79, 510]]]

    def __init__(self):
        self.sample = [[[413], [-848, -730], [313, -355, -98], [409, 544, -803, 845]],
                       [[416], [203, -513], [-547, -46, 318], [-727, -606, -64, -155]],
                       [[850], [-753, 624], [315, 701, 671], [-418, -65, -124, -865]],
                       [[992], [735, -475], [-398, 318, -988], [649, 193, 753, 319]]]

    def reset_sample_value(self):
        """
        reset sample values

        Args:
            self

        Returns:
            sample_values: the new random sample values in range(-1000,1000)
        """
        # return [[1],[2],[3],[4]]*4=40 values as the random sample values
        sample_values = []
        for i in range(4):
            sample_values_in_ith_time = []
            for j in range(4):
                l = []
                for k in range(j+1):
                    l.append(random.randrange(0, 1000, 1))
                sample_values_in_ith_time.append(l)
            sample_values.append(sample_values_in_ith_time)
        self.sample = sample_values
        return sample_values


if __name__=="__main__":
    s = SampleValues()
    print(s.reset_sample_value())

