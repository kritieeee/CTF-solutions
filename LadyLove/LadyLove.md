# LadyLove writeup

## Description

Sir-Steals-A-Lot is a world famous art thief. Lately he stole this painting. When he was caught he claimed to have done it because the painting commemorates the location of the crowned glory of his lady love. They fell in love in her hometown but her grandfather wouldn't let her marry a thief like him.! Answer is the meaning of his LadyLove's last name. Wrap the answer in the flag. Example :BITSCTF{your_answer}

This challenge has a limit of 10 attempts This challenge has a follow up challenge called MoneyBinder.



Additionally , a hint was released :
16th February 2024 is his LadyLove's 111th birthday (if she were still alive)
![stolenpainting](https://github.com/kritieeee/CTF-solutions/blob/main/LadyLove/images-LadyLove/stolenpainting%20(1).jpeg)


## Solution
This is a pure OSINT search challenge.As such, we only have to pick up keywords or phrases from the question and search on Google to get the Flag.


On reverse image searching the image, we come to find out that it was painted by _Peter Adolf Hall_ and the painting is called _Landscape_

So when we google the abpve keywords we get the following result.

![screenshot1](https://github.com/kritieeee/CTF-solutions/blob/main/LadyLove/images-LadyLove/Screenshot%202024-02-21%20230839.png)


On opening the page on scrolling to the painting title we find the following information 



//input screenshot2.jpeg
This confirms that the painting was painted in 
_Spa,Belgium_.The second part of the question asks us to find a lady who was crowned in Spa.Therefore we googled the keywords _Lady crowned in Spa,Belgium_ which leads to the following result.


//screenshot 3 



Using the hint that was released, we can confirm that the LadyLove in question is really Keriman Halis Ece. Scrolling further down the Wikipedia page or another simple google search leads to the following result 


//screenshot 4



Hence, the final flag is BITSCTF{queen}



