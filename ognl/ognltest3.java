/***************************************************************************
 * Copyright (C) 2013 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 **************************************************************************/

/**
 * This is a standalone utility for testing OGNL expressions outside of PingFederate.
 * 
 * Point it a) to a file with an ONGL expression and b) to a file that contains a defined
 * set of attributes to test the expression against. The attributes file is a "java properties-like"
 * file that can contain multiple key entries to record multi-value attributes.
 * 
 * Sample attributes file:
 * 
 * name=Hans
 * email=hzandbelt@pingidentity.com
 * email=hans.zandbelt@gmail.com
 * singlevalueattribute=samplevalue
 * multivalueattribute=samplevalue1
 * multivalueattribute=samplevalue2
 * multivalueattribute=samplevalue3
 * 
 * 
 * 
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

import com.pingidentity.common.util.ognl.ExpressionCalculator;
import ognl.Ognl;
import java.io.*;
import java.util.*;

public class ognltest3 {
	public static void main(String[] args) throws Exception {

		if (args.length < 2) {
			System.err.println("Usage: [executable] <file-with-ongl-expression> <properties-like-file-with-attributes>");
			System.exit(0);
		}

		StringBuffer expr = new StringBuffer();
		String line = null;
		BufferedReader reader = new BufferedReader(new FileReader(args[0]));
		while ((line = reader.readLine()) != null) expr.append(line);

		Object parsedExpression = Ognl.parseExpression(expr.toString());

		Map<Object, Object> simpleAttributeMap = new HashMap<Object, Object>();
		ArrayList<String> list = null;
		org.sourceid.saml20.adapter.attribute.AttributeValue vals = null;

		reader = new BufferedReader(new FileReader(args[1]));
		while ((line = reader.readLine()) != null) {
			String[] s = line.split("=", 2);
			vals = (org.sourceid.saml20.adapter.attribute.AttributeValue) simpleAttributeMap.get((String) s[0]);
			list = (ArrayList<String>) ((vals == null) ? new ArrayList<String>() : vals.getValues());
			list.add(s[1]);
			System.err.println(" # adding property: name=" + s[0] + ", value=" + s[1]);
			simpleAttributeMap.put((String) s[0], new org.sourceid.saml20.adapter.attribute.AttributeValue(list));
		}

		Object value = ExpressionCalculator.calculate(parsedExpression, simpleAttributeMap, simpleAttributeMap);

		System.out.println(value.toString());
	}
}
